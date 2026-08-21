# Automatic recovery and guarded local rollout

This runbook applies to state format 4 (`tmuxgate 0.1.0.dev1` and later). It
does not authorize direct SSH, remote shell cleanup, manual lock deletion, or
manual socket deletion.

## What automatic mode does

On startup, and once per second while the broker is running, tmuxgate retries
only evidence-preserving actions for ordinary durable jobs:

| Durable or authenticated evidence | Automatic outcome |
| --- | --- |
| Connection/staging stopped before a wrapper request | `failed-pre-remote` |
| Requested/created wrapper, closed gate, no session/run/result, guarded discard succeeds | `failed-pre-remote` |
| Exact gated remote session exists | recreate/adopt viewer, then release the gate |
| Exact running session is detached | recreate/adopt and reattach its viewer |
| Authenticated complete result exists | detach finished viewer, collect, verify, spool, clean |
| Local verified spool exists | make the result available and retry exact cleanup |
| Command-start marker but no result or authoritative termination | remain blocked; show one TUI action |
| Legacy exact gated/running/complete job | upgrade only the positively proven phase, then reconcile normally |
| Legacy broad flag with missing artifacts or no exact identity | remain blocked; show one TUI action |

The TUI action is `Jobs` → `Resolve uncertainty` → `Acknowledge & unblock`.
Its evidence page is the complete decision boundary. It changes only the local
durable audit state, does not contact or clean a host, and does not assert
remote absence, completion, output, or an exit status. `Keep blocked` is
focused by default.

## Pre-rollout evidence and rollback copy

Run from the repository worktree. Do not proceed while a healthy job is active.
Record the exact output of:

```bash
pwd
git rev-parse HEAD
git status --short
tmuxgate --version
readlink -f "$HOME/.local/bin/tmuxgate"
tmuxgate runtime status
tmuxgate jobs --json
```

Before installation or restart, create an owner-only rollback directory and
copy the complete durable state, configuration, active-release link, and public
launcher link. `cp -a` preserves owner-only modes and symlink identities. The
rollout record must name the resulting directory without printing secrets:

```bash
rollback_root="$HOME/.local/share/tmuxgate/rollbacks/$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$rollback_root"
cp -a "$HOME/.local/state/tmuxgate" "$rollback_root/state"
cp -a "$HOME/.config/tmuxgate" "$rollback_root/config"
cp -a "$HOME/.local/share/tmuxgate/current" "$rollback_root/current"
cp -a "$HOME/.local/bin/tmuxgate" "$rollback_root/tmuxgate-launcher"
chmod -R go-rwx "$rollback_root"
```

If the application is accepting work, make a second copy after a normal TUI
quit and before installation. Never overwrite the first copy.

## Install and restart

Run the complete suite before publishing a release:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
bash -n src/tmuxgate/assets/remote_control.sh
git diff --check
```

Quit the foreground application through its TUI. Verify both lifecycle locks
are inactive or provably stale; do not delete either lock. Install through the
managed transaction, then start the new foreground TUI in the same trusted
terminal:

```bash
tmuxgate runtime status
./install.sh
tmuxgate
```

The installer does not restart tmuxgate and does not modify durable jobs or
verified spools.

## Post-rollout checks

In a separate local shell, collect:

```bash
tmuxgate --version
readlink -f "$HOME/.local/bin/tmuxgate"
tmuxgate runtime status
tmuxgate jobs --json
```

Both lock rows must be `active` with the same exact owner/lease identity; a PID
namespace may report that the live broker proved the exact nonce. The TUI must
show Ready, and the MCP listener must answer an authenticated read-only tool.
No pre-rollout durable request may disappear. Run the disposable fake-backend
automatic-recovery test from the installed interpreter; it creates only
temporary local state and contacts no configured machine:

```bash
installed_python="$(dirname "$(readlink -f "$HOME/.local/bin/tmuxgate")")/python"
PYTHONPATH=tests "$installed_python" -m unittest \
  test_automatic_recovery.AutomaticRecoveryTests.test_gate_release_observation_closes_both_missing_marker_windows \
  test_automatic_recovery.AutomaticRecoveryTests.test_complete_spool_with_detached_viewer_is_collected_and_cleaned -v
```

## Rollback without losing records

State format 4 is not readable by the older release. First quit the new TUI.
Make a new owner-only forward-recovery copy of the current state; never delete
it. If any request was approved after rollout, do not restore the old state
snapshot—repair or reinstall the new release so those records remain current.

If no request was approved after rollout, atomically move the current state
aside, restore the rollback snapshot with owner-only permissions, and point the
managed `current` symlink back to the recorded release. Preserve the moved
state until the incident is closed. Do not touch runtime locks or sockets;
normal startup reconciles only those it proves stale.

The installer retains prior managed releases. A rollback is therefore a local
release-link operation plus the compatible state snapshot, not a rebuild and
never a remote cleanup operation.

## Irreducible safety boundary

No local crash can prove what happened after a durable user-command-start
marker when the exact remote job offers neither a complete authenticated spool
nor authoritative termination evidence. tmuxgate intentionally does not
invent an exit status, infer absence from a missing pane, clean the uncertain
job, or retry the command. The single TUI acknowledgement is the only routine
operator workflow for that case.
