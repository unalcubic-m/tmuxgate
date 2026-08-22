# Changelog

## Unreleased

- Provide one automatic MCP-to-SSH execution path with exactly one remote tmux
  session per job.
- Persist atomic five-state local jobs with restart-safe result collection.
- Support explicit whole-job sudo, four MCP tools, and a three-job concurrency
  semaphore.
- Install with an ordinary Python tool and run through a non-root systemd user
  service with journald logs.
