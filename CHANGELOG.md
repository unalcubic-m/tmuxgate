# Changelog

## 0.1.0.dev1 - 2026-08-22

- Split ordinary remote execution into atomic durable connection, staging,
  wrapper, command-start, result, local-verification, and cleanup phases.
- Automatically reconcile safe staging failures, gated/running sessions,
  missing local viewers, complete authenticated spools, workstation restarts,
  and idempotent cleanup.
- Keep post-command uncertainty fail-closed and expose it as one explained,
  local-only TUI acknowledgement instead of a sequence of recovery commands.
- Preserve version-2/version-3 uncertainty without inferring absence; upgrade
  a legacy phase only from positive authenticated exact-job evidence.
- Bind lifecycle-lock adoption to PID, UID, boot ID, process start ticks,
  executable identity, creation time, instance/lease nonce, and a fresh
  same-UID broker challenge.
- Add crash/fault coverage for every phase, SSH status 255, lost viewers,
  local reboot replay, complete and incomplete spools, PID reuse, competing
  brokers, replayed owner proofs, guarded staging discard, and repeated
  reconciliation.

Rollback requires the pre-upgrade durable-state snapshot because older
releases cannot read state format 4. See
[docs/RECOVERY_RUNBOOK.md](docs/RECOVERY_RUNBOOK.md).
