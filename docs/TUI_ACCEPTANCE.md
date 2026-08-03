# TUI final acceptance evidence

This is the phase-6 requirement-to-evidence audit for issues #21 and #13. It
describes the shipped behavior on the default branch; a checked item means the
named implementation and automated evidence exist together. The complete test
and package matrix remains the final gate, so a named focused test is not used
to excuse a failing full suite.

## Evidence index

- `CLI`: `src/tmuxgate/cli.py` and
  `SettingsCommandTests.test_no_argument_cli_starts_the_unified_application`,
  `test_plain_is_explicit_and_preview_flag_is_removed`.
- `TUI`: `src/tmuxgate/textual_interface.py` and the complete
  `TextualOperatorInterfaceTests` headless suite.
- `PTY`: `TextualPtyLifecycleTests`, including the real default-CLI/explicit-
  plain startup test and normal, exception, signal, cancellation, subprocess,
  and external-handoff modes.
- `OI`: `src/tmuxgate/operator_interface.py` and the complete
  `DecisionPrimitiveTests`, `StructuredPromptTests`, `PromptQueueTests`, and
  `PlainTerminalInterfaceTests` suites.
- `APP`: `src/tmuxgate/application.py` and
  `UnifiedApplicationLifecycleTests`.
- `SSH`: `SecretPromptPresenterTests` in `tests/test_real_ssh.py`.
- `EXEC`: `RealExecutorTests` in `tests/test_executor.py`, plus the transport
  and durable-state suites.
- `RENDER`: `tests/test_approval.py`, including exact long-content, pager,
  terminal-control, bidi, default-denial, and machine-disable coverage.
- `CI`: `.github/workflows/ci.yml`, `docs/CI.md`, `tests/test_ci_policy.py`,
  protocol Hypothesis tests, and durable-state failure-injection tests.
- `PKG`: exact runtime pins in `pyproject.toml`, build/sdist/wheel validation,
  temporary wheel installation, `pip check`, and installed CLI smoke tests in
  private HOME/XDG directories outside the checkout.

## Issue #13 acceptance criteria

### User experience

- [x] No-argument startup opens the full-screen dashboard in a supported
  interactive terminal. Evidence: `CLI`; `PTY.test_default_cli_uses_tui_and_plain_remains_explicit`.
- [x] Prior shell history is hidden while the alternate screen is owned.
  Evidence: `PTY` asserts alternate-screen enter/leave sequences and that the
  plain dashboard is absent from default startup.
- [x] Exit restores previous terminal contents and modes. Evidence:
  `PTY.test_normal_exception_signal_and_cancellation_restore_terminal`.
- [x] Idle readiness, broker/MCP, approval, machine, prompt, job, connection,
  activity, and ownership state update in place. Evidence:
  `TUI.test_headless_dashboard_navigation_bounds_and_inert_rendering`,
  `test_connection_progress_replaces_request_projection_in_place`; `APP`.
- [x] Execution approval is a focused exact modal. Evidence:
  `TUI.test_execution_approval_views_resize_and_explicit_decisions`.
- [x] Deny is the approval default. Evidence: the same TUI test and
  `RENDER.test_execution_approval_defaults_to_deny_and_requires_explicit_yes`.
- [x] Exact code/script and complete technical details are independently
  reachable and scrollable. Evidence: `TUI` execution-modal test and RENDER
  long-script/exact-byte tests.
- [x] Connection progress replaces one request projection in place. Evidence:
  `TUI.test_connection_progress_replaces_request_projection_in_place`.
- [x] SSH failure has a concise reason plus complete inert diagnostics.
  Evidence: `TUI.test_retry_and_fallback_modals_are_exact_safe_and_separate`.
- [x] Retry defaults to Cancel and visibly enforces 1 of 1. Evidence: the same
  TUI test and `OI.test_plain_retry_cancel_is_default_and_diagnostics_are_inert`.
- [x] Fallback has a separate exact modal. Evidence: the same TUI test and
  `OI.test_fallback_requires_adjacent_exact_routes_and_truthful_mutation`.
- [x] Jobs, machines, activity, and queued requests are keyboard navigable.
  Evidence: `TUI.test_headless_dashboard_navigation_bounds_and_inert_rendering`.
- [x] Resizing preserves active decisions. Evidence: the execution-modal and
  machine-disable modal headless tests.
- [x] Below 72×20, the resize warning and safe action remain available while
  every positive action is disabled. Evidence:
  `TUI.test_machine_disable_modal_is_exact_bounded_and_safe_when_small` and the
  shared `_FailClosedDecisionScreen` size policy used by every modal.
- [x] `tmuxgate --plain` remains supported. Evidence: `CLI`; real `PTY` plain
  startup; installed package `--plain --help` smoke.

### Architecture

- [x] Broker/executor workers use `OperatorInterface`, not rendered decision
  UI. Evidence: `OI`; graph call-path audit; `APP` and `EXEC` wiring tests.
- [x] Immutable prompt objects carry exact request and binding identities.
  Evidence: `OI.test_execution_prompt_is_immutable_and_rejects_mismatched_identity`,
  retry/fallback/secret/machine-disable constructor tests.
- [x] A decision resolves its exact pending prompt at most once. Evidence:
  `OI.test_decision_resolves_exact_prompt_once` and prompt-ID reuse rejection.
- [x] Multiple prompts queue deterministically. Evidence:
  `OI.test_queue_is_fifo_and_close_denies_every_unresolved_prompt` and TUI
  active/queued tests.
- [x] Worker/UI communication uses the documented mutex-protected FIFO,
  per-prompt condition, presenter thread, `call_from_thread`, and original-
  object callback path. Evidence: `OI`, `TUI`, and architecture documentation.
- [x] Plain and TUI share prompt models, decision validation, and business
  policy. Evidence: `OI` plain parity tests and the complete TUI modal suite.
- [x] Exact pure renderers remain independently tested. Evidence: `RENDER`.
- [x] Textual is exactly pinned and package-tested. Evidence:
  `TextualDependencyTests`, `PKG`, and package CI.

### Safety

- [x] UI close, crash, shutdown, and runtime terminal loss deny unresolved
  decisions. Evidence: TUI close/runtime-loss tests; OI presenter exception,
  cancellation, abandonment, and close tests; `APP` shutdown ordering.
- [x] Pretyped input cannot approve a new modal. Evidence:
  `TUI.test_modal_boundary_flushes_kernel_input_or_fails_closed` and
  `test_stale_input_and_modal_identity_cannot_approve_next_prompt`.
- [x] Remote output and protocol input cannot invoke actions. Evidence: inert
  non-markup widgets, no input data path, OI injected-terminal tests, approval
  stdin/socket tests, and SSH notification-without-attachment tests.
- [x] ANSI, control, bidi, links, and Textual markup render inertly. Evidence:
  TUI malicious rendering tests and RENDER terminal-control tests.
- [x] Existing approval/retry/fallback bindings remain exact. Evidence: OI
  constructor/worker validation and EXEC retry/fallback tests.
- [x] The TUI never captures secret bytes. Evidence:
  `PTY.test_external_process_owns_bytes_while_textual_is_suspended` asserts the
  external shell consumes the bytes while the TUI sees zero key events.
- [x] External handoff requires exact request-bound authorization. Evidence:
  OI secret binding tests and SSH exact-handoff/rejected-handoff tests.
- [x] Suspend restores terminal mode before attachment and redraws afterward.
  Evidence: PTY external success/failure tests and Textual ownership tests.
- [x] Failed TUI startup/runtime never changes approval policy, creates a plain
  replacement, or continues a second dashboard. It exits fail closed and says
  to restart explicitly with `--plain`. Evidence: APP startup ordering and
  `TUI.test_textual_exception_directs_explicit_plain_restart`.

### Documentation

- [x] README documents the dashboard and decision workflow.
- [x] Architecture documents the operator boundary, prompt queue, UI-thread
  messaging, ownership states, external handoff, and fail-closed lifecycle.
- [x] CLI help documents the default TUI and explicit `--plain`; the temporary
  `--tui` preview flag is rejected.
- [x] `SECURITY.md` separates presentation, trusted terminal input, untrusted
  remote/protocol output, and external terminal ownership.

## Issue #13 required tests

### Unit tests

- [x] Missing, malformed, and mismatched prompt bindings are rejected (`OI`).
- [x] Exactly-once resolution is enforced (`OI`).
- [x] Stale decisions cannot resolve replacements (`OI`, `TUI`).
- [x] Interface close denies every unresolved prompt (`OI`, `TUI`).
- [x] FIFO order is deterministic (`OI`).
- [x] Activity is bounded (`OI`, `TUI`).
- [x] Controls and markup remain inert (`RENDER`, `TUI`).
- [x] Approval defaults to Deny; retry defaults to Cancel; machine disable
  defaults to Keep enabled (`RENDER`, `TUI`, `OI`).

### Headless TUI tests

- [x] Idle dashboard opens and all views navigate.
- [x] Approval Summary, Code, and Technical Details switch independently.
- [x] Deliberate approve and deny paths are covered.
- [x] Unrelated keys do not resolve a prompt.
- [x] Multiple prompts queue and resolve independently.
- [x] Resize during an active decision preserves the exact prompt.
- [x] Long scripts/diagnostics/evidence retain complete content with a fixed,
  bounded widget tree.
- [x] Closing with active and queued prompts denies both.

All items above are exercised by `TextualOperatorInterfaceTests`; the final
phase also adds exact machine-disable, compact-size, and runtime-terminal-loss
cases.

### PTY and integration tests

- [x] Start/exit restores screen contents and terminal modes (`PTY`).
- [x] `--plain` works in an isolated real PTY (`PTY` default/plain CLI test).
- [x] Pretyped input cannot approve (`TUI` kernel flush plus PTY lifecycle).
- [x] Simulated remote output cannot control the UI (`TUI`, `SSH`).
- [x] Approval/connecting/running/completed transitions are structured and
  projected in place (`TUI`, `EXEC`, `APP`).
- [x] Retryable failure resolves only its matching worker (`TUI`, `OI`, `EXEC`).
- [x] Non-retryable/post-mutation failure exposes no Retry (`EXEC`).
- [x] Fallback requires its own exact decision (`TUI`, `OI`, `EXEC`).
- [x] Fake external suspend/resume restores terminal state (`PTY`).
- [x] Signal/exception/cancellation restore terminal state and deny prompts
  (`PTY`, `TUI`, `OI`).
- [x] Tests cannot use developer SSH configuration or real machines: required
  CI jobs use private HOME/XDG state, a poisoned `Host *` ProxyCommand, no SSH
  agent, and an asserted-absent contact marker (`CI`).

## Issue #21 final acceptance

- [x] Supported interactive startup defaults to Textual; `--plain` is explicit.
- [x] No silent fallback exists; all TUI failures direct explicit plain restart.
- [x] Unified broker/MCP/dashboard/operator/SSH/cleanup lifecycle remains one
  foreground application (`APP`).
- [x] All five decision types use exact structured boundaries and safe defaults.
- [x] Unresolved decisions deny on every shutdown path.
- [x] Stale input and all rendered/untrusted sources cannot invoke actions.
- [x] Complete scripts, diagnostics, hashes, plans, and bindings remain
  accessible with bounded widget creation.
- [x] Dashboard records and prompt projections are bounded.
- [x] Runtime dependencies are exact pins and package tested.
- [x] The real `TerminalArbiter.state` property is used correctly by the live
  dashboard snapshot; the real-CLI PTY regression covers this integration.
- [x] README, CLI help, architecture, CI, security, installation, terminal
  requirements, minimum size, startup failure, and recovery behavior agree.
- [x] Full unit/headless/PTY/integration, lint, type, shell, coverage, build,
  temporary install, installed CLI, and poisoned-SSH matrix gates are required.

## Related issue overlap (no issue-state automation)

### Issue #4

All nine acceptance criteria are satisfied by the implementation from PR #30
and the TUI handoff from PR #37: prompt matching is notification only; exact
operator confirmation binds request, machine, command, route, endpoint, and
viewer; only the trusted terminal can answer; secret permission remains
independent of disabled execution approval; unauthorized/stale recipients are
rejected; and deliberate `tmuxgate attach REQUEST_ID` remains. The seven named
regressions are represented by OI secret tests, SSH presenter tests, PTY secret-
byte isolation, application wiring, and manual-attach tests. This audit does
not change issue #4's state.

### Issue #5

All seven acceptance criteria and seven regressions remain satisfied by PR #24
and are reflected truthfully in the TUI: enrollment has explicit durable
mutation boundaries; uncertain/post-write enrollment blocks retry and fallback;
failures are durable; already-present keys remain read-only/idempotent; proven
pre-enrollment failures may use separately approved fallback; and durable and
displayed mutation states agree. Evidence is in EXEC, transport, SSH-key,
durable-state, and TUI recovery tests. This audit does not change issue #5's
state.

### Issue #9

All nine CI acceptance criteria and four regressions remain satisfied by PR
#31: Ruff, staged Pyright, ShellCheck, 75% branch coverage, protocol fuzzing,
durable failure injection, poisoned-SSH isolation, immutable Action SHAs, named
required checks, controlled checker violations, and installed-package smoke.
Phase 6 adds an explicit Textual/application adversarial step and isolated-XDG
installed CLI checks without absorbing unrelated hardening. This audit does not
change issue #9's state.
