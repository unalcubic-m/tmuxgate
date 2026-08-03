"""Textual dashboard and request-bound execution approval workflow."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
import os
import stat
import sys
import termios
import threading
import unicodedata

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Resize
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Static, TabbedContent, TabPane

from .approval import (
    ApprovalDecision,
    render_approval_document,
    render_approval_summary,
    render_code_document,
    render_fallback_approval_document,
    render_machine_disable_document,
    render_openssh_diagnostics,
    render_secret_input_authorization_document,
    render_ssh_retry_document,
)
from .operator_interface import (
    ActivityKind,
    ExecutionApprovalPrompt,
    MachineDisablePrompt,
    OperationalActivity,
    OperatorDecision,
    OperatorInterfaceError,
    OperatorPrompt,
    PlainTerminalInterface,
    QueuedPrompt,
    RouteFallbackPrompt,
    SecretInputAuthorizationPrompt,
    SshRetryPrompt,
)
from .terminal import TerminalArbiter, TerminalPriority


MINIMUM_COLUMNS = 72
MINIMUM_ROWS = 20
MAX_DASHBOARD_JOBS = 100
MAX_DASHBOARD_MACHINES = 256
MAX_DASHBOARD_PROMPTS = 100
MAX_RENDERED_ACTIVITY = 100
REFRESH_SECONDS = 0.20
APPROVAL_ARM_SECONDS = 0.35


def inert_text(value: object) -> str:
    """Return text with terminal controls inert and no markup interpretation."""

    text = str(value)
    rendered: list[str] = []
    for character in text:
        codepoint = ord(character)
        category = unicodedata.category(character)
        if codepoint <= 0xFF and (codepoint < 0x20 or 0x7F <= codepoint <= 0x9F):
            rendered.append(f"\\x{codepoint:02x}")
        elif category in {"Cc", "Cf", "Cs"}:
            rendered.append(
                f"\\u{codepoint:04x}" if codepoint <= 0xFFFF else f"\\U{codepoint:08x}"
            )
        else:
            rendered.append(character)
    return "".join(rendered)


def _stream_fd(stream: object, name: str) -> int:
    fileno = getattr(stream, "fileno", None)
    if not callable(fileno):
        raise OperatorInterfaceError(f"Textual {name} has no file descriptor")
    try:
        descriptor = fileno()
    except (OSError, ValueError) as exc:
        raise OperatorInterfaceError(
            f"Textual {name} file descriptor is unavailable"
        ) from exc
    if isinstance(descriptor, bool) or not isinstance(descriptor, int):
        raise OperatorInterfaceError(f"Textual {name} file descriptor is invalid")
    return descriptor


def validate_textual_terminal(
    stdin: object | None = None,
    stdout: object | None = None,
) -> None:
    """Require one foreground terminal for Textual input and output."""

    input_stream = sys.__stdin__ if stdin is None else stdin
    output_stream = sys.__stdout__ if stdout is None else stdout
    input_fd = _stream_fd(input_stream, "input")
    output_fd = _stream_fd(output_stream, "output")
    if not os.isatty(input_fd) or not os.isatty(output_fd):
        raise OperatorInterfaceError(
            "the TUI requires terminal input and output; restart explicitly "
            "with --plain"
        )
    input_metadata = os.fstat(input_fd)
    output_metadata = os.fstat(output_fd)
    if (
        not stat.S_ISCHR(input_metadata.st_mode)
        or not stat.S_ISCHR(output_metadata.st_mode)
        or input_metadata.st_rdev != output_metadata.st_rdev
    ):
        raise OperatorInterfaceError(
            "Textual input and output do not belong to one terminal; restart "
            "explicitly with --plain"
        )
    try:
        foreground = os.tcgetpgrp(input_fd)
    except OSError as exc:
        raise OperatorInterfaceError(
            "Textual could not verify foreground terminal ownership; restart "
            "explicitly with --plain"
        ) from exc
    if foreground != os.getpgrp():
        raise OperatorInterfaceError(
            "tmuxgate does not own the foreground terminal; refusing TUI startup; "
            "restart explicitly with --plain"
        )


def flush_textual_input(stream: object | None = None) -> None:
    """Discard kernel-buffered input at a new security-modal boundary."""

    input_stream = sys.__stdin__ if stream is None else stream
    descriptor = _stream_fd(input_stream, "input")
    if not os.isatty(descriptor):
        raise OperatorInterfaceError("Textual input is no longer a terminal")
    try:
        termios.tcflush(descriptor, termios.TCIFLUSH)
    except (OSError, termios.error) as exc:
        raise OperatorInterfaceError(
            "Textual could not discard buffered approval input"
        ) from exc


@dataclass(frozen=True, slots=True)
class DashboardMachine:
    alias: str
    description: str
    enabled: bool
    ssh_state: str


@dataclass(frozen=True, slots=True)
class DashboardJob:
    request_id: str
    machine_alias: str
    state: str
    updated_at: str
    active: bool


@dataclass(frozen=True, slots=True)
class DashboardRuntimeSnapshot:
    ready: bool = False
    listener: str = "not ready"
    approval_mode: str = "unknown"
    machines: tuple[DashboardMachine, ...] = field(default_factory=tuple)
    jobs: tuple[DashboardJob, ...] = field(default_factory=tuple)
    active_job_count: int | None = None
    terminal_owner: str = "Textual dashboard"


DashboardProvider = Callable[[], DashboardRuntimeSnapshot]


class TerminalOwnershipState(StrEnum):
    """Exclusive foreground ownership visible to the dashboard boundary."""

    TUI = "tui"
    MODAL = "modal"
    EXTERNAL = "external"


class _FailClosedDecisionScreen(ModalScreen[ApprovalDecision]):
    """Shared stale-input fence, safe default, and compact-size behavior."""

    SAFE_BUTTON_ID = ""
    POSITIVE_BUTTON_ID = ""

    def __init__(self) -> None:
        super().__init__()
        self._arm_ready = False
        self._compact = False
        self._finished = False

    def on_mount(self) -> None:
        self._apply_decision_size(self.size.width, self.size.height)
        self.call_after_refresh(self._initialize_controls)

    def on_resize(self, event: Resize) -> None:
        self._apply_decision_size(event.size.width, event.size.height)

    def _apply_decision_size(self, width: int, height: int) -> None:
        self._compact = width < MINIMUM_COLUMNS or height < MINIMUM_ROWS
        self.set_class(self._compact, "compact-decision")
        warnings = list(self.query(".decision-size-warning"))
        contents = list(self.query(".decision-content"))
        for warning in warnings:
            warning.display = self._compact
            if self._compact and isinstance(warning, Static):
                warning.update(
                    f"Terminal too small ({width}×{height}). Resize to at least "
                    f"{MINIMUM_COLUMNS}×{MINIMUM_ROWS} to inspect evidence and "
                    "enable the positive action. The safe action remains available."
                )
        for content in contents:
            content.display = not self._compact
        self._sync_positive_action()

    def _initialize_controls(self) -> None:
        self.query_one(f"#{self.SAFE_BUTTON_ID}", Button).focus()
        if not self.app.is_headless:
            try:
                flush_textual_input()
            except OperatorInterfaceError:
                self._finish(ApprovalDecision.DENIED)
                return
        self.set_timer(APPROVAL_ARM_SECONDS, self._arm_decision)

    def _arm_decision(self) -> None:
        if self._finished:
            return
        self._arm_ready = True
        self._sync_positive_action()

    def _sync_positive_action(self) -> None:
        if not self.is_mounted:
            return
        safe = self.query_one(f"#{self.SAFE_BUTTON_ID}", Button)
        positive = self.query_one(f"#{self.POSITIVE_BUTTON_ID}", Button)
        positive.disabled = not self._arm_ready or self._compact
        if self._compact or not self._arm_ready:
            safe.focus()

    def action_safe_default(self) -> None:
        self._finish(ApprovalDecision.DENIED)

    def _finish(self, decision: ApprovalDecision) -> None:
        if self._finished:
            return
        self._finished = True
        self.dismiss(decision)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == self.SAFE_BUTTON_ID:
            self._finish(ApprovalDecision.DENIED)
        elif (
            event.button.id == self.POSITIVE_BUTTON_ID
            and self._arm_ready
            and not self._compact
        ):
            self._finish(ApprovalDecision.APPROVED)


class ExecutionApprovalScreen(_FailClosedDecisionScreen):
    """One immutable execution prompt rendered as a fail-closed modal."""

    CSS = """
    ExecutionApprovalScreen {
        align: center middle;
        background: $background 80%;
    }
    #approval-dialog {
        width: 100%;
        max-width: 110;
        height: 100%;
        border: heavy $accent;
        background: $surface;
        padding: 1 2;
    }
    #approval-heading { height: 2; text-style: bold; }
    #approval-views { height: 1fr; }
    .approval-document { height: 1fr; overflow: auto; padding: 1; }
    #approval-actions { height: 3; align-horizontal: right; }
    #approval-actions Button { margin-left: 1; min-width: 12; }
    .decision-size-warning {
        display: none;
        height: 1fr;
        content-align: center middle;
        text-align: center;
        color: $warning;
        padding: 0 1;
    }
    ExecutionApprovalScreen.compact-decision #approval-dialog { padding: 0 1; }
    ExecutionApprovalScreen.compact-decision #approval-heading { display: none; }
    """
    BINDINGS = [
        Binding("escape", "safe_default", "Deny", priority=True),
        Binding("s", "show_view('approval-summary')", "Summary"),
        Binding("c", "show_view('approval-code')", "Code"),
        Binding("t", "show_view('approval-technical')", "Technical details"),
    ]
    SAFE_BUTTON_ID = "approval-deny"
    POSITIVE_BUTTON_ID = "approval-approve"

    def __init__(self, prompt: ExecutionApprovalPrompt) -> None:
        if not isinstance(prompt, ExecutionApprovalPrompt):
            raise TypeError("prompt must be an ExecutionApprovalPrompt")
        super().__init__()
        self.prompt = prompt

    def compose(self) -> ComposeResult:
        prompt = self.prompt
        with Vertical(id="approval-dialog"):
            yield Static(
                "Execution approval\nRequest ID: " + inert_text(prompt.request_id),
                markup=False,
                id="approval-heading",
            )
            yield Static(
                "",
                markup=False,
                classes="decision-size-warning",
            )
            with TabbedContent(
                initial="approval-summary",
                id="approval-views",
                classes="decision-content",
            ):
                with TabPane("Summary", id="approval-summary"):
                    yield Static(
                        render_approval_summary(
                            prompt.request_id,
                            prompt.request,
                            prompt.connection_plan,
                        ),
                        markup=False,
                        classes="approval-document",
                        id="approval-summary-document",
                    )
                with TabPane("Code", id="approval-code"):
                    yield Static(
                        render_code_document(prompt.request_id, prompt.request),
                        markup=False,
                        classes="approval-document",
                        id="approval-code-document",
                    )
                with TabPane("Technical Details", id="approval-technical"):
                    yield Static(
                        render_approval_document(
                            prompt.request_id,
                            prompt.request,
                            prompt.connection_plan,
                        ),
                        markup=False,
                        classes="approval-document",
                        id="approval-technical-document",
                    )
            with Horizontal(id="approval-actions"):
                yield Button("Deny", variant="error", id="approval-deny")
                yield Button(
                    "Approve",
                    variant="success",
                    id="approval-approve",
                    disabled=True,
                )

    def action_show_view(self, view_id: str) -> None:
        self.query_one("#approval-views", TabbedContent).active = view_id


class RecoveryDecisionScreen(_FailClosedDecisionScreen):
    """Shared safe mechanics for exact retry and fallback recovery prompts."""

    CSS = """
    SshRetryScreen, RouteFallbackScreen {
        align: center middle;
        background: $background 80%;
    }
    #recovery-dialog {
        width: 100%;
        max-width: 110;
        height: 100%;
        border: heavy $warning;
        background: $surface;
        padding: 1 2;
    }
    #recovery-heading { height: 3; text-style: bold; }
    #recovery-views { height: 1fr; }
    .recovery-document { height: 1fr; overflow: auto; padding: 1; }
    #recovery-actions { height: 3; align-horizontal: right; }
    #recovery-actions Button { margin-left: 1; min-width: 14; }
    .decision-size-warning {
        display: none;
        height: 1fr;
        content-align: center middle;
        text-align: center;
        color: $warning;
        padding: 0 1;
    }
    .compact-decision #recovery-dialog { padding: 0 1; }
    .compact-decision #recovery-heading { display: none; }
    """
    BINDINGS = [
        Binding("escape", "safe_default", "Cancel", priority=True),
        Binding("s", "show_view('recovery-summary')", "Summary"),
        Binding("d", "show_view('recovery-diagnostics')", "Diagnostics"),
        Binding("b", "show_view('recovery-binding')", "Binding evidence"),
    ]
    SAFE_BUTTON_ID = "recovery-cancel"
    POSITIVE_BUTTON_ID = "recovery-approve"

    def __init__(self, prompt: SshRetryPrompt | RouteFallbackPrompt) -> None:
        if not isinstance(prompt, (SshRetryPrompt, RouteFallbackPrompt)):
            raise TypeError("prompt must be an SSH retry or route fallback prompt")
        super().__init__()
        self.prompt = prompt

    def _summary(self) -> tuple[str, str, str]:
        prompt = self.prompt
        safe = inert_text
        endpoints = {
            item.resolved.endpoint_id: item.resolved
            for item in prompt.connection_plan.endpoints
        }
        if isinstance(prompt, SshRetryPrompt):
            endpoint = endpoints[prompt.endpoint_id]
            heading = "SSH setup retry"
            approve_label = "Retry once"
            summary = "\n".join(
                (
                    f"Request ID: {safe(prompt.request_id)}",
                    f"Machine: {safe(prompt.request.machine_alias)}",
                    f"Endpoint: {safe(prompt.endpoint_id)}",
                    "Target: "
                    f"{safe(endpoint.configured_address)}:"
                    f"{safe(endpoint.configured_port)}",
                    "Resolved identity: "
                    f"{safe(endpoint.resolved_user)}@"
                    f"{safe(endpoint.resolved_hostname)}:"
                    f"{safe(endpoint.resolved_port)}",
                    f"Failure: {safe(prompt.failure_detail)}",
                    f"Remote command: {safe(prompt.remote_command_state.value)}",
                    f"Remote mutation: {safe(prompt.remote_mutation_state.value)}",
                    "Permitted retry: "
                    f"{safe(prompt.retry_number)} of {safe(prompt.retry_limit)}",
                    "Cancel is the safe default.",
                )
            )
        else:
            failed = endpoints[prompt.failed_endpoint_id]
            fallback = endpoints[prompt.fallback_endpoint_id]
            heading = "Separate route fallback authorization"
            approve_label = "Use fallback"
            summary = "\n".join(
                (
                    f"Request ID: {safe(prompt.request_id)}",
                    f"Machine: {safe(prompt.request.machine_alias)}",
                    f"Failed route: {safe(prompt.failed_endpoint_id)} "
                    f"({safe(failed.configured_address)}:"
                    f"{safe(failed.configured_port)})",
                    "Failed identity: "
                    f"{safe(failed.resolved_user)}@"
                    f"{safe(failed.resolved_hostname)}:"
                    f"{safe(failed.resolved_port)}",
                    f"Failure: {safe(prompt.failure_detail)}",
                    f"Proposed route: {safe(prompt.fallback_endpoint_id)} "
                    f"({safe(fallback.configured_address)}:"
                    f"{safe(fallback.configured_port)})",
                    "Proposed identity: "
                    f"{safe(fallback.resolved_user)}@"
                    f"{safe(fallback.resolved_hostname)}:"
                    f"{safe(fallback.resolved_port)}",
                    f"Remote command: {safe(prompt.remote_command_state.value)}",
                    f"Remote mutation: {safe(prompt.remote_mutation_state.value)}",
                    "A separate decision is required because the original RUN "
                    "approval does not authorize route fallback.",
                    "Cancel is the safe default.",
                )
            )
        return heading, approve_label, summary

    def _binding_document(self) -> str:
        prompt = self.prompt
        if isinstance(prompt, SshRetryPrompt):
            return render_ssh_retry_document(
                prompt.request_id,
                prompt.request,
                prompt.connection_plan,
                endpoint_id=prompt.endpoint_id,
                failure_detail=prompt.failure_detail,
                remote_mutation_started=False,
                openssh_diagnostics=prompt.openssh_diagnostics,
                openssh_diagnostics_sha256=prompt.openssh_diagnostics_sha256,
                remote_command_state=prompt.remote_command_state.value,
                retry_number=prompt.retry_number,
                retry_limit=prompt.retry_limit,
                retry_binding_sha256=prompt.retry_binding_sha256,
                prompt_id=prompt.prompt_id,
            )
        return render_fallback_approval_document(
            prompt.request_id,
            prompt.request,
            prompt.connection_plan,
            failed_endpoint_id=prompt.failed_endpoint_id,
            fallback_endpoint_id=prompt.fallback_endpoint_id,
            failure_detail=prompt.failure_detail,
            remote_mutation_started=False,
            openssh_diagnostics=prompt.openssh_diagnostics,
            openssh_diagnostics_sha256=prompt.openssh_diagnostics_sha256,
            remote_command_state=prompt.remote_command_state.value,
            fallback_binding_sha256=prompt.fallback_binding_sha256,
            prompt_id=prompt.prompt_id,
        )

    def compose(self) -> ComposeResult:
        heading, approve_label, summary = self._summary()
        prompt = self.prompt
        diagnostics = (
            f"OpenSSH diagnostics SHA-256: "
            f"{prompt.openssh_diagnostics_sha256}\n"
            f"Exact byte length: {len(prompt.openssh_diagnostics)}\n\n"
            + render_openssh_diagnostics(prompt.openssh_diagnostics)
        )
        with Vertical(id="recovery-dialog"):
            yield Static(
                heading + "\nRequest ID: " + inert_text(prompt.request_id),
                markup=False,
                id="recovery-heading",
            )
            yield Static(
                "",
                markup=False,
                classes="decision-size-warning",
            )
            with TabbedContent(
                initial="recovery-summary",
                id="recovery-views",
                classes="decision-content",
            ):
                with TabPane("Summary", id="recovery-summary"):
                    yield Static(
                        summary,
                        markup=False,
                        classes="recovery-document",
                        id="recovery-summary-document",
                    )
                with TabPane("Diagnostics", id="recovery-diagnostics"):
                    yield Static(
                        diagnostics,
                        markup=False,
                        classes="recovery-document",
                        id="recovery-diagnostics-document",
                    )
                with TabPane("Binding Evidence", id="recovery-binding"):
                    yield Static(
                        self._binding_document(),
                        markup=False,
                        classes="recovery-document",
                        id="recovery-binding-document",
                    )
            with Horizontal(id="recovery-actions"):
                yield Button("Cancel", variant="error", id="recovery-cancel")
                yield Button(
                    approve_label,
                    variant="warning",
                    id="recovery-approve",
                    disabled=True,
                )

    def action_show_view(self, view_id: str) -> None:
        self.query_one("#recovery-views", TabbedContent).active = view_id


class SshRetryScreen(RecoveryDecisionScreen):
    """Focused bounded-retry decision for one exact SSH failure."""

    def __init__(self, prompt: SshRetryPrompt) -> None:
        if not isinstance(prompt, SshRetryPrompt):
            raise TypeError("prompt must be an SshRetryPrompt")
        super().__init__(prompt)


class RouteFallbackScreen(RecoveryDecisionScreen):
    """Separate authorization for one exact adjacent fallback route."""

    def __init__(self, prompt: RouteFallbackPrompt) -> None:
        if not isinstance(prompt, RouteFallbackPrompt):
            raise TypeError("prompt must be a RouteFallbackPrompt")
        super().__init__(prompt)


class MachineDisableScreen(_FailClosedDecisionScreen):
    """Local machine-disable decision bound to one exhausted request."""

    CSS = """
    MachineDisableScreen {
        align: center middle;
        background: $background 80%;
    }
    #disable-dialog {
        width: 100%;
        max-width: 110;
        height: 100%;
        border: heavy $warning;
        background: $surface;
        padding: 1 2;
    }
    #disable-heading { height: 3; text-style: bold; }
    #disable-views { height: 1fr; }
    .disable-document { height: 1fr; overflow: auto; padding: 1; }
    #disable-actions { height: 3; align-horizontal: right; }
    #disable-actions Button { margin-left: 1; min-width: 16; }
    .decision-size-warning {
        display: none;
        height: 1fr;
        content-align: center middle;
        text-align: center;
        color: $warning;
        padding: 0 1;
    }
    MachineDisableScreen.compact-decision #disable-dialog { padding: 0 1; }
    MachineDisableScreen.compact-decision #disable-heading { display: none; }
    """
    BINDINGS = [
        Binding("escape", "safe_default", "Keep enabled", priority=True),
        Binding("s", "show_view('disable-summary')", "Summary"),
        Binding("r", "show_view('disable-request')", "Request evidence"),
        Binding("b", "show_view('disable-binding')", "Binding evidence"),
    ]
    SAFE_BUTTON_ID = "disable-cancel"
    POSITIVE_BUTTON_ID = "disable-approve"

    def __init__(self, prompt: MachineDisablePrompt) -> None:
        if not isinstance(prompt, MachineDisablePrompt):
            raise TypeError("prompt must be a MachineDisablePrompt")
        super().__init__()
        self.prompt = prompt

    def compose(self) -> ComposeResult:
        prompt = self.prompt
        summary = render_machine_disable_document(
            prompt.request_id,
            prompt.request.machine_alias,
            failure_detail=prompt.failure_detail,
            remote_mutation_started=False,
        )
        request_evidence = render_approval_document(
            prompt.request_id,
            prompt.request,
            prompt.connection_plan,
        )
        binding = "\n".join(
            (
                "=== tmuxgate machine-disable binding ===",
                f"prompt_id: {inert_text(prompt.prompt_id)}",
                f"request_id: {inert_text(prompt.request_id)}",
                "machine: " + inert_text(prompt.request.machine_alias),
                "connection_plan_sha256: "
                + inert_text(prompt.connection_plan.plan_sha256),
                "remote_mutation_state: "
                + inert_text(prompt.remote_mutation_state.value),
                "machine_disable_binding_sha256: "
                + inert_text(prompt.binding_sha256),
                "=== end tmuxgate machine-disable binding ===",
            )
        )
        with Vertical(id="disable-dialog"):
            yield Static(
                "Machine unavailable\nRequest ID: "
                + inert_text(prompt.request_id),
                markup=False,
                id="disable-heading",
            )
            yield Static("", markup=False, classes="decision-size-warning")
            with TabbedContent(
                initial="disable-summary",
                id="disable-views",
                classes="decision-content",
            ):
                with TabPane("Summary", id="disable-summary"):
                    yield Static(
                        summary,
                        markup=False,
                        classes="disable-document",
                        id="disable-summary-document",
                    )
                with TabPane("Request Evidence", id="disable-request"):
                    yield Static(
                        request_evidence,
                        markup=False,
                        classes="disable-document",
                        id="disable-request-document",
                    )
                with TabPane("Binding Evidence", id="disable-binding"):
                    yield Static(
                        binding,
                        markup=False,
                        classes="disable-document",
                        id="disable-binding-document",
                    )
            with Horizontal(id="disable-actions"):
                yield Button(
                    "Keep enabled",
                    variant="primary",
                    id="disable-cancel",
                )
                yield Button(
                    "Disable machine",
                    variant="warning",
                    id="disable-approve",
                    disabled=True,
                )

    def action_show_view(self, view_id: str) -> None:
        self.query_one("#disable-views", TabbedContent).active = view_id


class SecretInputAuthorizationScreen(_FailClosedDecisionScreen):
    """Exact, independently authorized handoff to one remote recipient."""

    CSS = """
    SecretInputAuthorizationScreen {
        align: center middle;
        background: $background 80%;
    }
    #secret-dialog {
        width: 100%;
        max-width: 110;
        height: 100%;
        border: heavy $error;
        background: $surface;
        padding: 1 2;
    }
    #secret-heading { height: 3; text-style: bold; }
    #secret-document { height: 1fr; overflow: auto; padding: 1; }
    #secret-actions { height: 3; align-horizontal: right; }
    #secret-actions Button { margin-left: 1; min-width: 14; }
    .decision-size-warning {
        display: none;
        height: 1fr;
        content-align: center middle;
        text-align: center;
        color: $warning;
        padding: 0 1;
    }
    SecretInputAuthorizationScreen.compact-decision #secret-dialog { padding: 0 1; }
    SecretInputAuthorizationScreen.compact-decision #secret-heading { display: none; }
    """
    BINDINGS = [Binding("escape", "safe_default", "Deny", priority=True)]
    SAFE_BUTTON_ID = "secret-deny"
    POSITIVE_BUTTON_ID = "secret-approve"

    def __init__(self, prompt: SecretInputAuthorizationPrompt) -> None:
        if not isinstance(prompt, SecretInputAuthorizationPrompt):
            raise TypeError("prompt must be a SecretInputAuthorizationPrompt")
        super().__init__()
        self.prompt = prompt

    def compose(self) -> ComposeResult:
        prompt = self.prompt
        document = render_secret_input_authorization_document(
            prompt.request_id,
            prompt.request,
            prompt.connection_plan,
            prompt_id=prompt.prompt_id,
            endpoint_id=prompt.endpoint_id,
            viewer_session_id=prompt.viewer_session_id,
            command_identity_sha256=prompt.command_identity_sha256,
            secret_input_binding_sha256=prompt.secret_input_binding_sha256,
        )
        with Vertical(id="secret-dialog"):
            yield Static(
                "Secret input requested\n"
                "Deny unless you intend to hand the terminal directly to "
                + inert_text(prompt.viewer_session_id),
                markup=False,
                id="secret-heading",
            )
            yield Static(
                document,
                markup=False,
                id="secret-document",
                classes="decision-content",
            )
            yield Static("", markup=False, classes="decision-size-warning")
            with Horizontal(id="secret-actions"):
                yield Button("Deny", variant="error", id="secret-deny")
                yield Button(
                    "Forward input",
                    variant="warning",
                    id="secret-approve",
                    disabled=True,
                )



class TmuxgateDashboardApp(App[None]):
    """Bounded dashboard with one request-bound approval modal at a time."""

    TITLE = "tmuxgate"
    SUB_TITLE = "operator interface"
    CSS = """
    Screen { layout: vertical; }
    #minimum-warning {
        display: none;
        height: 1fr;
        content-align: center middle;
        text-align: center;
        color: $warning;
        padding: 1 2;
    }
    #views { height: 1fr; }
    .panel { padding: 1 2; height: 1fr; overflow-y: auto; }
    """
    BINDINGS = [
        Binding("d", "show_view('dashboard')", "Dashboard"),
        Binding("j", "show_view('jobs')", "Jobs"),
        Binding("m", "show_view('machines')", "Machines"),
        Binding("a", "show_view('activity')", "Activity"),
        Binding("r", "show_view('requests')", "Requests"),
        Binding("?", "show_view('help')", "Help"),
        Binding("q", "quit_dashboard", "Quit", priority=True),
    ]

    def __init__(
        self,
        interface: "TextualOperatorInterface",
        stop: threading.Event,
        config: object,
    ) -> None:
        super().__init__()
        self.interface = interface
        self.external_stop = stop
        self.config = config
        self.snapshot_failure: BaseException | None = None
        self.minimum_size = False
        self._active_decision: QueuedPrompt | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", markup=False, id="minimum-warning")
        with TabbedContent(id="views"):
            with TabPane("Dashboard", id="dashboard"):
                yield Static(
                    "Starting…",
                    markup=False,
                    classes="panel",
                    id="dashboard-content",
                )
            with TabPane("Jobs", id="jobs"):
                yield Static(
                    "No durable jobs.",
                    markup=False,
                    classes="panel",
                    id="jobs-content",
                )
            with TabPane("Machines", id="machines"):
                yield Static(
                    "No configured machines.",
                    markup=False,
                    classes="panel",
                    id="machines-content",
                )
            with TabPane("Activity", id="activity"):
                yield Static(
                    "No recent activity.",
                    markup=False,
                    classes="panel",
                    id="activity-content",
                )
            with TabPane("Queued requests", id="requests"):
                yield Static(
                    "No queued requests.",
                    markup=False,
                    classes="panel",
                    id="requests-content",
                )
            with TabPane("Help", id="help"):
                yield Static(
                    "Full-screen operator interface\n\n"
                    "d  dashboard    j  jobs       m  machines\n"
                    "a  activity     r  requests   ?  help\n"
                    "q  stop tmuxgate\n\n"
                    "Execution approvals, bounded SSH retries, and separate "
                    "route fallbacks open one at a time with a safe default. "
                    "Secret-input handoffs require a separate exact decision; "
                    "the TUI then suspends while the trusted viewer owns the "
                    "terminal. Exhausted-machine disable decisions use a "
                    "separate local-mutation modal.",
                    markup=False,
                    classes="panel",
                )
        yield Footer()

    def on_mount(self) -> None:
        self.interface._dashboard_mounted(self)
        self.set_interval(REFRESH_SECONDS, self.refresh_snapshot)
        self._apply_size(self.size.width, self.size.height)
        self.refresh_snapshot()

    def on_unmount(self) -> None:
        self.interface._dashboard_unmounted(self)

    def on_resize(self, event: Resize) -> None:
        self._apply_size(event.size.width, event.size.height)

    def _apply_size(self, width: int, height: int) -> None:
        self.minimum_size = width < MINIMUM_COLUMNS or height < MINIMUM_ROWS
        warning = self.query_one("#minimum-warning", Static)
        views = self.query_one("#views", TabbedContent)
        warning.display = self.minimum_size
        views.display = not self.minimum_size
        if self.minimum_size:
            warning.update(
                f"Terminal too small ({width}×{height}). "
                f"Resize to at least {MINIMUM_COLUMNS}×{MINIMUM_ROWS}. "
                "Press q to exit."
            )

    def action_show_view(self, view_id: str) -> None:
        if self.minimum_size:
            return
        self.query_one("#views", TabbedContent).active = view_id

    def action_quit_dashboard(self) -> None:
        self.interface.fail_closed()
        self.external_stop.set()
        self.exit()

    def present_operator_decision(self, queued: QueuedPrompt) -> None:
        """Present one exact supported prompt without reconstructing identity."""

        if not isinstance(
            queued.prompt,
            (
                ExecutionApprovalPrompt,
                SshRetryPrompt,
                RouteFallbackPrompt,
                SecretInputAuthorizationPrompt,
                MachineDisablePrompt,
            ),
        ):
            queued.pending.deny()
            return
        if self._active_decision is not None:
            queued.pending.deny()
            return
        if not self.interface._begin_modal(queued.prompt):
            queued.pending.deny()
            return
        self._active_decision = queued

        def complete(result: ApprovalDecision | None) -> None:
            self._complete_operator_decision(queued, result)

        if isinstance(queued.prompt, ExecutionApprovalPrompt):
            screen: ModalScreen[ApprovalDecision] = ExecutionApprovalScreen(
                queued.prompt
            )
        elif isinstance(queued.prompt, SshRetryPrompt):
            screen = SshRetryScreen(queued.prompt)
        elif isinstance(queued.prompt, SecretInputAuthorizationPrompt):
            screen = SecretInputAuthorizationScreen(queued.prompt)
        elif isinstance(queued.prompt, MachineDisablePrompt):
            screen = MachineDisableScreen(queued.prompt)
        else:
            screen = RouteFallbackScreen(queued.prompt)
        self.push_screen(screen, complete)

    def _complete_operator_decision(
        self,
        queued: QueuedPrompt,
        result: ApprovalDecision | None,
    ) -> None:
        """Resolve only the immutable queued item that owns the active modal."""

        if self._active_decision is not queued:
            return
        self._active_decision = None
        decision = (
            result if isinstance(result, ApprovalDecision) else ApprovalDecision.DENIED
        )
        self.interface._resolve_modal(queued, decision)

    def run_external_terminal_session(
        self,
        prompt: SecretInputAuthorizationPrompt,
        session: Callable[[], None],
    ) -> None:
        """Suspend Textual and run one previously reserved trusted session."""

        if self._active_decision is not None:
            raise OperatorInterfaceError(
                "cannot hand off the terminal while a modal owns the UI"
            )
        self.interface._validate_external_reservation(prompt)
        try:
            with self.interface.terminal.claim(
                priority=TerminalPriority.SECRET,
                purpose=f"secret input for request {prompt.request_id}",
                flush_input=False,
            ):
                with self.suspend():
                    session()
        finally:
            self.interface._finish_external_session(prompt)
            self.refresh(repaint=True, layout=True)

    def refresh_snapshot(self) -> None:
        if self.external_stop.is_set():
            self.exit()
            return
        try:
            self.interface.validate_runtime_terminal()
            snapshot = self.interface.dashboard_snapshot(self.config)
            self._render_dashboard(snapshot)
            self._render_jobs(snapshot.jobs)
            self._render_machines(snapshot.machines)
            self._render_activity(self.interface.activity_history)
            self._render_requests(self.interface.queued_prompts)
        except BaseException as exc:
            self.snapshot_failure = exc
            self.external_stop.set()
            self.exit(return_code=70)

    @staticmethod
    def _text(lines: list[str]) -> str:
        return "\n".join(lines)

    def _render_dashboard(self, snapshot: DashboardRuntimeSnapshot) -> None:
        active = (
            sum(job.active for job in snapshot.jobs)
            if snapshot.active_job_count is None
            else snapshot.active_job_count
        )
        latest_connections: dict[str, OperationalActivity] = {}
        for event in self.interface.activity_history:
            if event.kind is ActivityKind.CONNECTION and event.request_id is not None:
                latest_connections[event.request_id] = event
        connection_lines = [
            f"{request_id[:8]}={event.connection_phase.value}"
            + (
                f"@{inert_text(event.endpoint_id)}"
                if event.endpoint_id is not None
                else ""
            )
            + (
                f" mutation={event.remote_mutation_state.value}"
                if event.remote_mutation_state is not None
                else ""
            )
            for request_id, event in latest_connections.items()
            if event.connection_phase is not None
        ]
        lines = [
            "Application readiness: " + ("ready" if snapshot.ready else "starting"),
            "Broker readiness: " + ("ready" if snapshot.ready else "starting"),
            "MCP listener: " + inert_text(snapshot.listener),
            "Approval mode: " + inert_text(snapshot.approval_mode),
            f"Configured machines: {len(snapshot.machines)}",
            f"Active durable jobs: {active}",
            f"Pending prompts: {self.interface.pending_prompt_count}",
            "SSH / connection state: "
            + inert_text(
                ", ".join(
                    f"{machine.alias}={machine.ssh_state}"
                    for machine in snapshot.machines
                )
                or "none"
            ),
            "Request connection progress: "
            + inert_text(", ".join(connection_lines) or "none"),
            f"Recent activity: {len(self.interface.activity_history)} "
            f"(bounded to {self.interface.activity_capacity})",
            "Terminal ownership: " + inert_text(snapshot.terminal_owner),
        ]
        self.query_one("#dashboard-content", Static).update(self._text(lines))

    def _render_jobs(self, jobs: tuple[DashboardJob, ...]) -> None:
        bounded = jobs[-MAX_DASHBOARD_JOBS:]
        lines = ["REQUEST ID                        MACHINE            STATE"]
        lines.extend(
            f"{inert_text(job.request_id):32}  "
            f"{inert_text(job.machine_alias):17}  {inert_text(job.state)}"
            for job in bounded
        )
        if not bounded:
            lines.append("No durable jobs.")
        self.query_one("#jobs-content", Static).update(self._text(lines))

    def _render_machines(self, machines: tuple[DashboardMachine, ...]) -> None:
        bounded = machines[:MAX_DASHBOARD_MACHINES]
        lines = ["ALIAS              ENABLED  SSH STATE       DESCRIPTION"]
        lines.extend(
            f"{inert_text(machine.alias):18} "
            f"{('yes' if machine.enabled else 'no'):8} "
            f"{inert_text(machine.ssh_state):15} "
            f"{inert_text(machine.description)}"
            for machine in bounded
        )
        if not bounded:
            lines.append("No configured machines.")
        self.query_one("#machines-content", Static).update(self._text(lines))

    def _render_activity(self, activity: tuple[OperationalActivity, ...]) -> None:
        bounded = activity[-MAX_RENDERED_ACTIVITY:]
        lines = []
        for event in bounded:
            phase = (
                f"/{event.connection_phase.value}"
                if event.connection_phase is not None
                else ""
            )
            lines.append(
                f"{inert_text(event.kind.value + phase):24} {inert_text(event.message)}"
            )
        if not lines:
            lines.append("No recent activity.")
        self.query_one("#activity-content", Static).update(self._text(lines))

    def _render_requests(self, prompts: tuple[QueuedPrompt, ...]) -> None:
        bounded = prompts[-MAX_DASHBOARD_PROMPTS:]
        lines: list[str] = []
        for item in bounded:
            prompt = item.prompt
            state = "resolved" if item.pending.resolved else "pending"
            lines.append(
                f"#{item.sequence} {state} {type(prompt).__name__} "
                f"request={inert_text(prompt.request_id)} "
                f"machine={inert_text(prompt.request.machine_alias)}"
            )
        if not lines:
            lines.append("No queued requests.")
        self.query_one("#requests-content", Static).update(self._text(lines))


class TextualOperatorInterface(PlainTerminalInterface):
    """Textual UI with UI-thread execution decisions and fail-closed shutdown."""

    def __init__(
        self,
        terminal: TerminalArbiter,
        *,
        approval_mode: str = "always",
        activity_capacity: int = 256,
        prompt_capacity: int = MAX_DASHBOARD_PROMPTS,
        validate_terminal: bool = True,
        terminal_validator: Callable[[], None] | None = None,
        app_factory: Callable[
            ["TextualOperatorInterface", threading.Event, object],
            TmuxgateDashboardApp,
        ] = TmuxgateDashboardApp,
    ) -> None:
        if approval_mode not in {"always", "disabled"}:
            raise ValueError("approval_mode must be 'always' or 'disabled'")
        if type(validate_terminal) is not bool:
            raise TypeError("validate_terminal must be boolean")
        if terminal_validator is None:
            terminal_validator = validate_textual_terminal
        if not callable(terminal_validator):
            raise TypeError("terminal_validator must be callable")
        self._terminal_validator = terminal_validator if validate_terminal else None
        if validate_terminal:
            terminal_validator()
        if (
            isinstance(prompt_capacity, bool)
            or not isinstance(prompt_capacity, int)
            or not 1 <= prompt_capacity <= 65536
        ):
            raise ValueError("prompt_capacity must be between 1 and 65536")
        if not callable(app_factory):
            raise TypeError("app_factory must be callable")
        self._queued_lock = threading.Lock()
        self._queued: deque[QueuedPrompt] = deque(maxlen=prompt_capacity)
        self._pending_prompt_count = 0
        self._submitted_sequence = 0
        self._dashboard_provider: DashboardProvider | None = None
        self._app_factory = app_factory
        self._app_lock = threading.Lock()
        self._app_ready = threading.Event()
        self._active_app: TmuxgateDashboardApp | None = None
        self._ownership_lock = threading.Lock()
        self._ownership_state = TerminalOwnershipState.TUI
        self._external_prompt_id: str | None = None
        self._ui_available = threading.Event()
        self._ui_available.set()
        super().__init__(
            terminal,
            approval_mode=approval_mode,
            activity_capacity=activity_capacity,
        )

    @property
    def activity_capacity(self) -> int:
        assert self._activity.maxlen is not None
        return self._activity.maxlen

    @property
    def queued_prompts(self) -> tuple[QueuedPrompt, ...]:
        with self._queued_lock:
            return tuple(self._queued)

    @property
    def pending_prompt_count(self) -> int:
        with self._queued_lock:
            return self._pending_prompt_count

    @property
    def terminal_ownership_state(self) -> TerminalOwnershipState:
        with self._ownership_lock:
            return self._ownership_state

    def _begin_modal(self, prompt: OperatorPrompt) -> bool:
        del prompt
        with self._ownership_lock:
            if self._ownership_state is not TerminalOwnershipState.TUI:
                return False
            self._ownership_state = TerminalOwnershipState.MODAL
            self._ui_available.clear()
            return True

    def _complete_modal(
        self,
        prompt: OperatorPrompt,
        decision: ApprovalDecision,
    ) -> None:
        with self._ownership_lock:
            if self._ownership_state is not TerminalOwnershipState.MODAL:
                raise OperatorInterfaceError("modal terminal ownership was lost")
            if (
                isinstance(prompt, SecretInputAuthorizationPrompt)
                and decision is ApprovalDecision.APPROVED
            ):
                self._ownership_state = TerminalOwnershipState.EXTERNAL
                self._external_prompt_id = prompt.prompt_id
                return
            self._ownership_state = TerminalOwnershipState.TUI
            self._ui_available.set()

    def _resolve_modal(
        self,
        queued: QueuedPrompt,
        decision: ApprovalDecision,
    ) -> bool:
        """Atomically bind an approved secret slot to its handoff reservation."""

        with self._ownership_lock:
            if self._ownership_state is not TerminalOwnershipState.MODAL:
                raise OperatorInterfaceError("modal terminal ownership was lost")
            reserve = (
                isinstance(queued.prompt, SecretInputAuthorizationPrompt)
                and decision is ApprovalDecision.APPROVED
            )
            if reserve:
                self._ownership_state = TerminalOwnershipState.EXTERNAL
                self._external_prompt_id = queued.prompt.prompt_id
            else:
                self._ownership_state = TerminalOwnershipState.TUI
            resolved = queued.pending.resolve(
                OperatorDecision.for_prompt(queued.prompt, decision)
            )
            if not resolved:
                self._external_prompt_id = None
                self._ownership_state = TerminalOwnershipState.TUI
            if self._ownership_state is TerminalOwnershipState.TUI:
                self._ui_available.set()
            return resolved

    def _validate_external_reservation(
        self, prompt: SecretInputAuthorizationPrompt
    ) -> None:
        with self._ownership_lock:
            if (
                self._ownership_state is not TerminalOwnershipState.EXTERNAL
                or self._external_prompt_id != prompt.prompt_id
            ):
                raise OperatorInterfaceError(
                    "external terminal session lacks exact authorization"
                )

    def _finish_external_session(self, prompt: SecretInputAuthorizationPrompt) -> None:
        with self._ownership_lock:
            if self._external_prompt_id != prompt.prompt_id:
                raise OperatorInterfaceError(
                    "external terminal reservation identity changed"
                )
            self._external_prompt_id = None
            self._ownership_state = TerminalOwnershipState.TUI
            self._ui_available.set()

    def bind_dashboard_provider(self, provider: DashboardProvider) -> None:
        if not callable(provider):
            raise TypeError("dashboard provider must be callable")
        if self._dashboard_provider is not None:
            raise OperatorInterfaceError("dashboard provider is already bound")
        self._dashboard_provider = provider

    def dashboard_snapshot(self, config: object) -> DashboardRuntimeSnapshot:
        if self._dashboard_provider is not None:
            snapshot = self._dashboard_provider()
            if not isinstance(snapshot, DashboardRuntimeSnapshot):
                raise OperatorInterfaceError(
                    "dashboard provider returned invalid state"
                )
            return snapshot
        broker = getattr(config, "broker", None)
        mcp = getattr(config, "mcp", None)
        machines = getattr(config, "machines", {})
        return DashboardRuntimeSnapshot(
            approval_mode=str(getattr(broker, "approval_mode", "unknown")),
            listener=(
                f"http://{getattr(mcp, 'host', '?')}:{getattr(mcp, 'port', '?')}/mcp"
            ),
            machines=tuple(
                DashboardMachine(
                    alias=str(alias),
                    description=str(getattr(machine, "description", "")),
                    enabled=bool(getattr(machine, "enabled", True)),
                    ssh_state="unknown",
                )
                for alias, machine in sorted(machines.items())
            )[:MAX_DASHBOARD_MACHINES],
        )

    def _request(self, prompt: OperatorPrompt) -> OperatorDecision:
        with self._queued_lock:
            pending = self._prompts.submit(prompt)
            queued = QueuedPrompt(self._submitted_sequence, prompt, pending)
            self._submitted_sequence += 1
            self._queued.append(queued)
            self._pending_prompt_count += 1
        if isinstance(prompt, ExecutionApprovalPrompt):
            message = "Execution approval is waiting for an explicit decision."
        elif isinstance(prompt, SshRetryPrompt):
            message = (
                "One bounded same-endpoint SSH retry is waiting for an exact decision."
            )
        elif isinstance(prompt, RouteFallbackPrompt):
            message = (
                "A separately bound route fallback is waiting for an exact decision."
            )
        elif isinstance(prompt, SecretInputAuthorizationPrompt):
            message = (
                "A remote pane requested secret input. Exact independent "
                "authorization is required before terminal handoff."
            )
        else:
            message = None
        if message is not None:
            self.publish_activity(
                OperationalActivity.create(
                    ActivityKind.STATUS,
                    message,
                    request_id=prompt.request_id,
                    machine_name=prompt.request.machine_alias,
                )
            )
        try:
            return pending.wait()
        except BaseException:
            pending.abandon()
            raise
        finally:
            with self._queued_lock:
                self._pending_prompt_count -= 1

    def _presentation_loop(self) -> None:
        while not self._prompts.closed:
            queued = self._prompts.next_prompt()
            if queued is None:
                return
            if queued.pending.resolved:
                continue
            try:
                if not isinstance(
                    queued.prompt,
                    (
                        ExecutionApprovalPrompt,
                        SshRetryPrompt,
                        RouteFallbackPrompt,
                        SecretInputAuthorizationPrompt,
                        MachineDisablePrompt,
                    ),
                ):
                    queued.pending.deny()
                    self.publish_activity(
                        OperationalActivity.create(
                            ActivityKind.STATUS,
                            "This TUI phase denied an unsupported operator decision.",
                            request_id=queued.prompt.request_id,
                            machine_name=queued.prompt.request.machine_alias,
                        )
                    )
                    continue
                while not self._prompts.closed:
                    if not self._ui_available.wait(0.10):
                        continue
                    if not self._app_ready.wait(0.10):
                        continue
                    with self._app_lock:
                        app = self._active_app
                    if app is None:
                        continue
                    app.call_from_thread(app.present_operator_decision, queued)
                    break
                queued.pending.wait()
            except BaseException as exc:
                self._failure = exc
                self._prompts.close()
                return

    def _dashboard_mounted(self, app: TmuxgateDashboardApp) -> None:
        with self._app_lock:
            if self._active_app is not None and self._active_app is not app:
                raise OperatorInterfaceError("another Textual app already owns the UI")
            self._active_app = app
            self._app_ready.set()

    def _dashboard_unmounted(self, app: TmuxgateDashboardApp) -> None:
        with self._app_lock:
            if self._active_app is app:
                self._active_app = None
                self._app_ready.clear()
        self._prompts.close()

    def fail_closed(self) -> None:
        self._prompts.close()
        self._app_ready.set()

    def validate_runtime_terminal(self) -> None:
        """Re-prove foreground terminal ownership while Textual is active."""

        validator = self._terminal_validator
        if validator is not None:
            validator()

    def run_external_terminal_session(
        self,
        prompt: SecretInputAuthorizationPrompt,
        session: Callable[[], None],
    ) -> None:
        if not isinstance(prompt, SecretInputAuthorizationPrompt):
            raise TypeError("prompt must be a SecretInputAuthorizationPrompt")
        if not callable(session):
            raise TypeError("external terminal session must be callable")
        self._validate_external_reservation(prompt)
        while not self._prompts.closed:
            if not self._app_ready.wait(0.10):
                continue
            with self._app_lock:
                app = self._active_app
            if app is None:
                continue
            app.call_from_thread(app.run_external_terminal_session, prompt, session)
            return
        self._finish_external_session(prompt)
        raise OperatorInterfaceError("dashboard closed before terminal handoff")

    def publish_activity(self, event: OperationalActivity) -> None:
        if not isinstance(event, OperationalActivity):
            raise TypeError("event must be an OperationalActivity")
        with self._activity_lock:
            self._activity.append(event)

    def run_dashboard(self, stop: threading.Event, config: object) -> None:
        self.validate_runtime_terminal()
        app = self._app_factory(self, stop, config)
        if not isinstance(app, TmuxgateDashboardApp):
            raise OperatorInterfaceError("Textual app factory returned invalid app")
        try:
            try:
                app.run()
            except BaseException as exc:
                raise OperatorInterfaceError(
                    "the full-screen TUI failed; restart explicitly with --plain"
                ) from exc
        finally:
            self.fail_closed()
        if app.snapshot_failure is not None:
            raise OperatorInterfaceError(
                "the full-screen TUI lost terminal or status ownership "
                f"({inert_text(app.snapshot_failure)}); "
                "restart explicitly with --plain"
            ) from app.snapshot_failure
        if app.return_code != 0:
            raise OperatorInterfaceError(
                f"the full-screen TUI exited with status {app.return_code}; "
                "restart explicitly with --plain"
            )

    def close(self) -> bool:
        self._app_ready.set()
        return super().close()
