"""Read-only Textual operator dashboard for the phase-two TUI preview."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
import os
import stat
import sys
import threading
import unicodedata

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.events import Resize
from textual.widgets import Footer, Header, Static, TabbedContent, TabPane

from .operator_interface import (
    ActivityKind,
    OperationalActivity,
    OperatorInterfaceError,
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
            "the read-only TUI requires terminal input and output; use --plain"
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


class TmuxgateDashboardApp(App[None]):
    """Fixed-widget, bounded, read-only dashboard."""

    TITLE = "tmuxgate"
    SUB_TITLE = "read-only TUI preview"
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
                    "Read-only preview\n\n"
                    "d  dashboard    j  jobs       m  machines\n"
                    "a  activity     r  requests   ?  help\n"
                    "q  stop tmuxgate\n\n"
                    "Approval, retry, fallback, and secret-input dialogs are "
                    "deliberately unavailable in phase 2. Use --plain for the "
                    "complete production decision path.",
                    markup=False,
                    classes="panel",
                )
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(REFRESH_SECONDS, self.refresh_snapshot)
        self._apply_size(self.size.width, self.size.height)
        self.refresh_snapshot()

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
        self.external_stop.set()
        self.exit()

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
    """Read-only Textual UI that preserves the phase-one decision boundary.

    Prompt requests are queued and visible but deliberately never resolved by
    the TUI. Closing the interface denies every waiter. This prevents Textual
    and the established direct terminal readers from competing before the
    later security-decision modal phases are implemented.
    """

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
                "the read-only TUI requires approval_mode='always'; "
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
        self._dashboard_provider: DashboardProvider | None = None
        self._app_factory = app_factory
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

    def _presentation_loop(self) -> None:
        while not self._prompts.closed:
            queued = self._prompts.next_prompt()
            if queued is None:
                return
            with self._queued_lock:
                self._queued.append(queued)
                self._pending_prompt_count += 1
            self.publish_activity(
                OperationalActivity.create(
                    ActivityKind.STATUS,
                    "Read-only TUI queued an operator decision; use --plain "
                    "after restart to use the complete decision path.",
                    request_id=queued.prompt.request_id,
                    machine_name=queued.prompt.request.machine_alias,
                )
            )

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
        self._active_app = app
        try:
            app.run()
        finally:
            self._active_app = None
        if app.snapshot_failure is not None:
            raise OperatorInterfaceError(
                "Textual dashboard status refresh failed"
            ) from app.snapshot_failure
        if app.return_code != 0:
            raise OperatorInterfaceError(
                f"Textual dashboard exited with status {app.return_code}"
            )
