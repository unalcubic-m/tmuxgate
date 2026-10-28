# Changelog

## Unreleased

- Support the native Windows foreground broker with protected owner-only ACLs,
  native atomic publication, and AppData defaults; keep remote targets Linux-only.
- Enforce strict SSH host checking and exclusive broker recovery; reap local SSH
  children safely during cancellation without rerunning ambiguous jobs.
- Add Windows/Linux CI, native security and subprocess tests, and Windows setup
  documentation. Windows service installation remains deferred.
- Provide one automatic MCP-to-SSH execution path with exactly one remote tmux
  session per job.
- Persist atomic five-state local jobs with restart-safe result collection.
- Support explicit whole-job sudo, four MCP tools, and a three-job concurrency
  semaphore.
- Install with an ordinary Python tool and run through a non-root systemd user
  service with journald logs.
