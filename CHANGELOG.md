# Changelog

## Unreleased

- Replace the former multi-layer application with one automatic MCP-to-SSH
  execution path and exactly one remote tmux session per job.
- Add atomic five-state local jobs, restart-safe result collection, explicit
  whole-job sudo, four MCP tools, and a three-job concurrency semaphore.
- Remove all interactive operation, local session/viewing code, route and SSH
  policy frameworks, internal execution protocol, and custom installation
  machinery.
- Install with an ordinary Python tool and run through a non-root systemd user
  service with journald logs.
