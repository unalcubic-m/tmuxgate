"""Textual dashboard and request-bound execution approval workflow."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
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
)
from .operator_interface import (
    ActivityKind,
    ExecutionApprovalPrompt,
    OperationalActivity,
    OperatorDecision,
    OperatorInterfaceError,
    OperatorPrompt,
    PlainTerminalInterface,
    QueuedPrompt,
)
from .terminal import TerminalArbiter


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
                f"\\u{codepoint:04x}"
                if codepoint <= 0xFFFF
                else f"\\U{codepoint:08x}"
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
            "the TUI requires terminal input and output; use --plain"
        )
    input_metadata = os.fstat(input_fd)
    output_metadata = os.fstat(output_fd)
    if (
        not stat.S_ISCHR(input_metadata.st_mode)
        or not stat.S_ISCHR(output_metadata.st_mode)
        or input_metadata.st_rdev != output_metadata.st_rdev
    ):
        raise OperatorInterfaceError(
            "Textual input and output do not belong to one terminal; use --plain"
        )
    try:
        foreground = os.tcgetpgrp(input_fd)
    except OSError as exc:
        raise OperatorInterfaceError(
            "Textual could not verify foreground terminal ownership"
        ) from exc
    if foreground != os.getpgrp():
        raise OperatorInterfaceError(
            "tmuxgate does not own the foreground terminal; refusing TUI startup"
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


class ExecutionApprovalScreen(ModalScreen[ApprovalDecision]):
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
    """
    BINDINGS = [
        Binding("escape", "deny", "Deny", priority=True),
        Binding("s", "show_view('approval-summary')", "Summary"),
        Binding("c", "show_view('approval-code')", "Code"),
        Binding("t", "show_view('approval-technical')", "Technical details"),
    ]

    def __init__(self, prompt: ExecutionApprovalPrompt) -> None:
        if not isinstance(prompt, ExecutionApprovalPrompt):
            raise TypeError("prompt must be an ExecutionApprovalPrompt")
        super().__init__()
        self.prompt = prompt
        self._armed = False
        self._finished = False

    def compose(self) -> ComposeResult:
        prompt = self.prompt
        with Vertical(id="approval-dialog"):
            yield Static(
                "Execution approval\nRequest ID: " + inert_text(prompt.request_id),
                markup=False,
                id="approval-heading",
            )
            with TabbedContent(initial="approval-summary", id="approval-views"):
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

    def on_mount(self) -> None:
        self.call_after_refresh(self._initialize_controls)

    def _initialize_controls(self) -> None:
        deny = self.query_one("#approval-deny", Button)
        deny.focus()
        if not self.app.is_headless:
            try:
                flush_textual_input()
            except OperatorInterfaceError:
                self._finish(ApprovalDecision.DENIED)
                return
        # Input already buffered before this exact modal existed is consumed
        # while approval is disabled. A later, deliberate action is required.
        self.set_timer(APPROVAL_ARM_SECONDS, self._arm_approval)

    def _arm_approval(self) -> None:
        if self._finished:
            return
        self.query_one("#approval-deny", Button).focus()
        self._armed = True
        self.query_one("#approval-approve", Button).disabled = False

    def action_show_view(self, view_id: str) -> None:
        self.query_one("#approval-views", TabbedContent).active = view_id

    def action_deny(self) -> None:
        self._finish(ApprovalDecision.DENIED)

    def _finish(self, decision: ApprovalDecision) -> None:
        if self._finished:
            return
        self._finished = True
        self.dismiss(decision)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        event.stop()
        if event.button.id == "approval-deny":
            self._finish(ApprovalDecision.DENIED)
        elif event.button.id == "approval-approve" and self._armed:
            self._finish(ApprovalDecision.APPROVED)


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
        self._active_approval: QueuedPrompt | None = None

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
                    "Operator interface preview\n\n"
                    "d  dashboard    j  jobs       m  machines\n"
                    "a  activity     r  requests   ?  help\n"
                    "q  stop tmuxgate\n\n"
                    "Execution approvals open one at a time with Deny as the "
                    "safe default. Retry, fallback, machine-disable, and "
                    "secret-input decisions remain unavailable in this phase.",
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

    def present_execution_approval(self, queued: QueuedPrompt) -> None:
        """Push an exact prompt from the presenter thread onto the UI thread."""

        if not isinstance(queued.prompt, ExecutionApprovalPrompt):
            queued.pending.deny()
            return
        if self._active_approval is not None:
            queued.pending.deny()
            return
        self._active_approval = queued

        def complete(result: ApprovalDecision | None) -> None:
            self._complete_execution_approval(queued, result)

        self.push_screen(ExecutionApprovalScreen(queued.prompt), complete)

    def _complete_execution_approval(
        self,
        queued: QueuedPrompt,
        result: ApprovalDecision | None,
    ) -> None:
        """Resolve only the immutable queued item that owns the active modal."""

        if self._active_approval is not queued:
            return
        self._active_approval = None
        decision = (
            result if isinstance(result, ApprovalDecision) else ApprovalDecision.DENIED
        )
        queued.pending.resolve(
            OperatorDecision.for_prompt(queued.prompt, decision)
        )

    def refresh_snapshot(self) -> None:
        if self.external_stop.is_set():
            self.exit()
            return
        try:
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
        lines = [
            f"{inert_text(event.kind.value):12} {inert_text(event.message)}"
            for event in bounded
        ]
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
        app_factory: Callable[
            ["TextualOperatorInterface", threading.Event, object],
            TmuxgateDashboardApp,
        ] = TmuxgateDashboardApp,
    ) -> None:
        if approval_mode != "always":
            raise OperatorInterfaceError(
                "the TUI requires approval_mode='always'; "
                "use --plain for approval_mode='disabled'"
            )
        if type(validate_terminal) is not bool:
            raise TypeError("validate_terminal must be boolean")
        if validate_terminal:
            validate_textual_terminal()
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
                raise OperatorInterfaceError("dashboard provider returned invalid state")
            return snapshot
        broker = getattr(config, "broker", None)
        mcp = getattr(config, "mcp", None)
        machines = getattr(config, "machines", {})
        return DashboardRuntimeSnapshot(
            approval_mode=str(getattr(broker, "approval_mode", "unknown")),
            listener=(
                f"http://{getattr(mcp, 'host', '?')}:"
                f"{getattr(mcp, 'port', '?')}/mcp"
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
            self.publish_activity(
                OperationalActivity.create(
                    ActivityKind.STATUS,
                    "Execution approval is waiting for an explicit decision.",
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
                if not isinstance(queued.prompt, ExecutionApprovalPrompt):
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
                    if not self._app_ready.wait(0.10):
                        continue
                    with self._app_lock:
                        app = self._active_app
                    if app is None:
                        continue
                    app.call_from_thread(app.present_execution_approval, queued)
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

    def publish_activity(self, event: OperationalActivity) -> None:
        if not isinstance(event, OperationalActivity):
            raise TypeError("event must be an OperationalActivity")
        with self._activity_lock:
            self._activity.append(event)

    def run_dashboard(self, stop: threading.Event, config: object) -> None:
        validate_textual_terminal()
        app = self._app_factory(self, stop, config)
        if not isinstance(app, TmuxgateDashboardApp):
            raise OperatorInterfaceError("Textual app factory returned invalid app")
        try:
            app.run()
        finally:
            self.fail_closed()
        if app.snapshot_failure is not None:
            raise OperatorInterfaceError(
                "Textual dashboard status refresh failed"
            ) from app.snapshot_failure
        if app.return_code != 0:
            raise OperatorInterfaceError(
                f"Textual dashboard exited with status {app.return_code}"
            )

    def close(self) -> bool:
        self._app_ready.set()
        return super().close()
