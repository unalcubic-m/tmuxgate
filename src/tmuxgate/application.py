"""One-process lifecycle for the broker, MCP server, and terminal dashboard."""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import signal
import threading
from typing import Callable

from tmuxgate.approval import ApprovalDecision
from tmuxgate.availability import MachineAvailabilityRegistry
from tmuxgate.broker import BrokerServer
from tmuxgate.broker_api import BrokerControlService
from tmuxgate.config import AppConfig, Machine, load_config
from tmuxgate.connection_plan import ConnectionPlan
from tmuxgate.executor import RealExecutor
from tmuxgate.fake import FakeExecution
from tmuxgate.mcp_server import (
    DEFAULT_CONTROL_WORKERS,
    BrokerCallPools,
    EmbeddedMcpServer,
    create_mcp_server,
)
from tmuxgate.models import RequestSpec
from tmuxgate.operator_interface import (
    ActivityKind,
    ExecutionApprovalPrompt,
    OperationalActivity,
    OperatorInterface,
    PlainTerminalInterface,
    require_operator_decision,
)
from tmuxgate.planning import BoundRequestPlanner
from tmuxgate.real_remote import (
    LocalCollectionBudget,
    RealRemoteJobBackend,
    prepare_collection_directory,
)
from tmuxgate.real_ssh import (
    SecretPromptPresenter,
    SshChannelRunner,
    SubprocessMasterBackend,
)
from tmuxgate.runtime import (
    acquire_state_lock,
    load_or_create_mcp_token,
    open_broker_listener,
    prepare_runtime_layout,
)
from tmuxgate.spool import ResultSpool
from tmuxgate.settings import set_machine_enabled
from tmuxgate.scheduler import RequestState
from tmuxgate.ssh import ResolvedSshEndpoint, resolve_ssh_endpoint
from tmuxgate.ssh_key import AutoSshKeyManager
from tmuxgate.state import DurableStateStore, recover_startup
from tmuxgate.terminal import TerminalArbiter
from tmuxgate.textual_interface import (
    DashboardJob,
    DashboardMachine,
    DashboardRuntimeSnapshot,
    TextualOperatorInterface,
)
from tmuxgate.transport import MasterTransportPool


EXIT_SOFTWARE = 70
Dashboard = Callable[[threading.Event, TerminalArbiter, AppConfig], None]
# A bounded shutdown can report live injected/remote workers.  Keep every
# dependency they may still reference strongly reachable until interpreter
# exit; ExitStack deliberately does not run callbacks from __del__.
_RETAINED_SHUTDOWN_RESOURCES: list[ExitStack] = []


class RecoveryBlockedError(RuntimeError):
    """Startup recovery found one or more jobs that may still be running."""


class _ZeroFakeExecutor:
    def __call__(self, request_id: str, request: RequestSpec) -> FakeExecution:
        del request_id, request
        return FakeExecution()


def _approve_without_prompt(*arguments: object, **keywords: object) -> ApprovalDecision:
    del arguments, keywords
    return ApprovalDecision.APPROVED


class UnifiedApplication:
    """Own every long-running tmuxgate component as one foreground service."""

    def __init__(
        self,
        *,
        config_path: Path | str,
        socket_path: Path | str | None = None,
        state_dir: Path | str | None = None,
        fake: bool = False,
        dashboard: Dashboard | None = None,
        terminal: TerminalArbiter | None = None,
        operator_interface: OperatorInterface | None = None,
        textual: bool = False,
    ) -> None:
        self._config_path = Path(config_path)
        self._socket_path = socket_path
        self._state_dir = state_dir
        self._fake = bool(fake)
        self._dashboard = dashboard
        self._terminal = TerminalArbiter() if terminal is None else terminal
        self._operator_interface = operator_interface
        self._textual = bool(textual)
        self._stop = threading.Event()

    @property
    def stop_event(self) -> threading.Event:
        return self._stop

    def request_stop(self) -> None:
        self._stop.set()

    def _install_signal_handlers(self) -> dict[int, object]:
        if threading.current_thread() is not threading.main_thread():
            return {}

        def request_stop(signum: int, frame: object) -> None:
            del signum, frame
            self.request_stop()

        previous: dict[int, object] = {}
        try:
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, request_stop)
        except BaseException:
            self._restore_signal_handlers(previous)
            raise
        return previous

    @staticmethod
    def _restore_signal_handlers(previous: dict[int, object]) -> None:
        for number, handler in previous.items():
            signal.signal(number, handler)

    def run(self) -> int:
        config = load_config(self._config_path)
        availability = MachineAvailabilityRegistry(config.machines)
        paths = prepare_runtime_layout(
            socket_path=self._socket_path,
            state_dir=self._state_dir,
        )
        bearer_token = load_or_create_mcp_token(paths.state_dir)
        if self._operator_interface is not None:
            operator = self._operator_interface
        elif self._textual:
            operator = TextualOperatorInterface(
                self._terminal,
                approval_mode=config.broker.approval_mode,
            )
        else:
            operator = PlainTerminalInterface(
                self._terminal,
                dashboard=self._dashboard,
                approval_mode=config.broker.approval_mode,
            )
        clean = True
        pool: MasterTransportPool | None = None
        prompt_presenter: SecretPromptPresenter | None = None
        broker: BrokerServer | None = None
        mcp_http: EmbeddedMcpServer | None = None
        previous: dict[int, object] = {}
        owned_components_clean = [True]
        operator_closed = [False]

        def close_operator() -> bool:
            if operator_closed[0]:
                return True
            result = operator.close()
            operator_closed[0] = True
            return result

        def report_error(message: str) -> None:
            try:
                operator.publish_activity(
                    OperationalActivity.create(ActivityKind.ERROR, message)
                )
            except BaseException:
                # The application is already failing closed.  A broken
                # presentation boundary must not mask the original failure.
                pass

        with ExitStack() as resources:
            resources.callback(close_operator)
            # The state-directory lock is the application singleton.  It must
            # precede recovery so a second invocation (even with a different
            # custom socket path) cannot rewrite live durable records.
            resources.enter_context(acquire_state_lock(paths.state_dir))
            store = resources.enter_context(DurableStateStore(paths.state_dir))
            spool = resources.enter_context(ResultSpool(paths.state_dir))
            recovery = recover_startup(store)
            if not recovery.safe_to_accept_new_approvals:
                blocked = ", ".join(recovery.blocking_request_ids)
                raise RecoveryBlockedError(
                    f"recovery blocks new approvals: {blocked}"
                )
            # The listener owns a second lock in its runtime directory.  The
            # state lock serializes recovery; this runtime lock separately
            # serializes stale-socket inspection and binding even when two
            # invocations select different state directories.
            lifecycle = resources.enter_context(
                open_broker_listener(paths.socket_path)
            )

            if self._fake:
                if config.broker.approval_mode == "always":
                    def approver(request_id: str, request: RequestSpec) -> ApprovalDecision:
                        prompt = ExecutionApprovalPrompt.create(
                            request_id,
                            request,
                            None,
                            unbound_fake=True,
                        )
                        return require_operator_decision(
                            prompt,
                            operator.request_execution_approval(prompt),
                        )
                else:
                    approver = _approve_without_prompt
                selected_executor = _ZeroFakeExecutor()
                def approval_discarder(request_id: str) -> None:
                    return None

                def delivery_observer(request_id: str, delivered: bool) -> None:
                    return None
            else:
                if config.broker.approval_mode == "always":
                    def bound_approver(
                        request_id: str,
                        request: RequestSpec,
                        connection_plan: ConnectionPlan,
                    ) -> ApprovalDecision:
                        prompt = ExecutionApprovalPrompt.create(
                            request_id,
                            request,
                            connection_plan,
                        )
                        return require_operator_decision(
                            prompt,
                            operator.request_execution_approval(prompt),
                        )

                    planner = BoundRequestPlanner(
                        config,
                        approver=bound_approver,
                        machine_enabled=availability.is_enabled,
                    )

                    def approver(request_id: str, request: RequestSpec) -> ApprovalDecision:
                        return planner(request_id, request)
                else:
                    planner = BoundRequestPlanner(
                        config,
                        approver=_approve_without_prompt,
                        machine_enabled=availability.is_enabled,
                    )
                    approver = planner

                def revalidate(resolved: ResolvedSshEndpoint) -> ResolvedSshEndpoint:
                    machine = config.machines[resolved.machine_name]
                    endpoint = next(
                        item
                        for item in machine.endpoints
                        if item.id == resolved.endpoint_id
                    )
                    return resolve_ssh_endpoint(machine, endpoint)

                pool = MasterTransportPool(
                    paths.control_dir,
                    backend=SubprocessMasterBackend(terminal_lock=self._terminal),
                    identity_revalidator=revalidate,
                    max_masters=config.broker.max_open_ssh_masters,
                    idle_timeout_seconds=(
                        config.broker.ssh_master_idle_timeout_seconds
                    ),
                    key_manager=AutoSshKeyManager(),
                )

                def close_pool() -> None:
                    assert pool is not None
                    try:
                        pool.close_idle()
                    except BaseException as exc:
                        owned_components_clean[0] = False
                        report_error(
                            f"tmuxgate: could not close all idle SSH masters: {exc}"
                        )

                resources.callback(close_pool)
                prompt_presenter = SecretPromptPresenter(
                    terminal_lock=self._terminal,
                    authorizer=operator.request_secret_input_authorization,
                    terminal_handoff=operator.run_external_terminal_session,
                    reporter=lambda message: operator.publish_activity(
                        OperationalActivity.create(
                            ActivityKind.SSH_PROMPT,
                            f"tmuxgate: {message}",
                        )
                    ),
                )

                def close_prompt_presenter() -> None:
                    assert prompt_presenter is not None
                    try:
                        if not prompt_presenter.close():
                            owned_components_clean[0] = False
                    except BaseException as exc:
                        owned_components_clean[0] = False
                        report_error(
                            f"tmuxgate: could not close the prompt presenter: {exc}"
                        )

                resources.callback(close_prompt_presenter)
                channels = SshChannelRunner(prompt_presenter=prompt_presenter)
                collection_dir = prepare_collection_directory(
                    paths.state_dir / "collections"
                )
                collection_budget = LocalCollectionBudget(
                    config.limits.max_aggregate_collection_bytes
                )

                def machine_disabler(machine_name: str) -> None:
                    def persist(name: str, expected_machine: Machine) -> None:
                        set_machine_enabled(
                            self._config_path,
                            name,
                            enabled=False,
                            expected_machine=expected_machine,
                        )

                    availability.disable_persistently(machine_name, persist)

                executor = RealExecutor(
                    planner=planner,
                    transports=pool,
                    state=store,
                    spool=spool,
                    operator_interface=operator,
                    backend_factory=lambda transport, recipient: RealRemoteJobBackend(
                        transport,
                        channels=channels,
                        secret_input_recipient=recipient,
                        viewer_dir=paths.viewer_dir,
                        collection_dir=collection_dir,
                        limits=config.limits,
                        collection_budget=collection_budget,
                    ),
                    machine_disabler=machine_disabler,
                    machine_enabled=availability.is_enabled,
                )
                selected_executor = executor
                approval_discarder = executor.discard_approval
                delivery_observer = executor.result_delivery_finished

            control_service = BrokerControlService(
                config.machines,
                store,
                spool,
                machine_enabled=availability.is_enabled,
            )
            run_worker_count = config.broker.max_pending_requests + 2
            control_worker_count = DEFAULT_CONTROL_WORKERS
            broker = BrokerServer(
                lifecycle.listener,
                allowed_machines=config.machines,
                machine_enabled=availability.is_enabled,
                approver=approver,
                executor=selected_executor,
                max_pending_requests=config.broker.max_pending_requests,
                max_active_remote_commands=config.broker.max_active_remote_commands,
                max_client_sessions=run_worker_count + control_worker_count,
                approval_discarder=approval_discarder,
                delivery_observer=delivery_observer,
                control_service=control_service,
                activity_publisher=operator.publish_activity,
            )
            call_pools = resources.enter_context(
                BrokerCallPools(run_worker_count, control_worker_count)
            )
            mcp_http = EmbeddedMcpServer(
                create_mcp_server(paths.socket_path, call_pools=call_pools),
                host=config.mcp.host,
                port=config.mcp.port,
                bearer_token=bearer_token,
                on_unexpected_exit=lambda _failure: self.request_stop(),
            )
            services_ready = [False]

            if isinstance(operator, TextualOperatorInterface):
                terminal_states = {
                    RequestState.CANCELLED_BEFORE_APPROVAL,
                    RequestState.DENIED,
                    RequestState.FAILED_PRE_REMOTE,
                    RequestState.FAILED_REMOTE_SETUP,
                    RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_REBOOT,
                    RequestState.ABANDONED_AFTER_OPERATOR_CONFIRMED_DEAD_PANE,
                    RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED,
                    RequestState.DONE,
                }

                def dashboard_snapshot() -> DashboardRuntimeSnapshot:
                    retained = set(pool.retained_machine_names()) if pool else set()
                    records = store.load_all()
                    jobs = tuple(
                        DashboardJob(
                            request_id=record.request_id,
                            machine_alias=record.machine_alias,
                            state=record.state.value,
                            updated_at=record.updated_at,
                            active=record.state not in terminal_states,
                        )
                        for record in records[-100:]
                    )
                    machines = tuple(
                        DashboardMachine(
                            alias=name,
                            description=machine.description,
                            enabled=availability.is_enabled(name),
                            ssh_state=(
                                "retained"
                                if name in retained
                                else "not used (fake)"
                                if self._fake
                                else "idle"
                            ),
                        )
                        for name, machine in sorted(config.machines.items())
                    )
                    terminal = self._terminal.state()
                    owner = (
                        terminal.purpose or "external terminal user"
                        if terminal.busy
                        else operator.terminal_ownership_state.value
                    )
                    return DashboardRuntimeSnapshot(
                        ready=services_ready[0],
                        listener=f"http://{config.mcp.host}:{config.mcp.port}/mcp",
                        approval_mode=config.broker.approval_mode,
                        machines=machines,
                        jobs=jobs,
                        active_job_count=sum(
                            record.state not in terminal_states for record in records
                        ),
                        terminal_owner=owner,
                    )

                operator.bind_dashboard_provider(dashboard_snapshot)
            previous = self._install_signal_handlers()
            try:
                broker.start()
                mcp_http.start()
                services_ready[0] = True
                self._report_started(
                    operator, config, paths.socket_path, paths.mcp_token_path
                )
                operator.run_dashboard(self._stop, config)
                self._stop.set()
                # The HTTP thread notifies the shared stop event if it dies
                # after readiness.  Turn that notification into a fatal
                # application error instead of silently continuing broker-only.
                mcp_http.raise_if_failed()
            finally:
                broker_clean = True
                mcp_clean = True
                if mcp_http is not None:
                    # Stop taking HTTP work before aborting broker sessions.  An
                    # in-flight MCP handler may be blocked in the internal
                    # synchronous Unix client, so joining it before broker.stop()
                    # would invert the dependency and consume the whole timeout.
                    try:
                        mcp_http.request_stop()
                    except BaseException as exc:
                        mcp_clean = False
                        report_error(
                            f"tmuxgate: could not signal the MCP server: {exc}"
                        )
                # Once no new HTTP work can enter, deny every pending prompt
                # before joining broker workers that may be waiting on one.
                try:
                    if not close_operator():
                        owned_components_clean[0] = False
                except BaseException as exc:
                    owned_components_clean[0] = False
                    report_error(
                        f"tmuxgate: could not close the operator interface: {exc}"
                    )
                if broker is not None:
                    try:
                        broker_clean = broker.stop()
                    except BaseException as exc:
                        broker_clean = False
                        report_error(
                            f"tmuxgate: could not stop the broker safely: {exc}"
                        )
                if mcp_http is not None:
                    try:
                        mcp_clean = mcp_http.stop() and mcp_clean
                    except BaseException as exc:
                        mcp_clean = False
                        report_error(
                            f"tmuxgate: could not stop the MCP server safely: {exc}"
                        )
                clean = broker_clean and mcp_clean and clean
                try:
                    self._restore_signal_handlers(previous)
                except BaseException as exc:
                    clean = False
                    report_error(
                        f"tmuxgate: could not restore signal handlers: {exc}"
                    )
                if not broker_clean or not mcp_clean:
                    # Live workers can still hold the state store, spool, SSH
                    # pool, or listener.  Closing those dependencies underneath
                    # them creates use-after-close races.  Keep ownership until
                    # the CLI process terminates and its workers can no longer
                    # access process-owned resources.
                    _RETAINED_SHUTDOWN_RESOURCES.append(resources.pop_all())
                    unfinished = []
                    if not broker_clean:
                        unfinished.append("a broker worker or client session")
                    if not mcp_clean:
                        unfinished.append("the MCP HTTP server thread")
                    report_error(
                        "tmuxgate: shutdown incomplete: "
                        + " and ".join(unfinished)
                        + " did not stop cleanly. New work is no longer accepted. "
                        "Internal resources will remain open only for the rest of "
                        "this process to avoid unsafe cleanup beneath a live worker; "
                        f"tmuxgate will return status {EXIT_SOFTWARE}. "
                        "An already-approved durable remote job may continue "
                        "independently; run 'tmuxgate jobs' after exit to inspect it."
                    )
        clean = owned_components_clean[0] and clean
        return 0 if clean else EXIT_SOFTWARE

    def _report_started(
        self,
        operator: OperatorInterface,
        config: AppConfig,
        socket_path: Path,
        token_path: Path,
    ) -> None:
        kind = "fake" if self._fake else "real"
        messages = (
            f"tmuxgate {kind} broker listening on {socket_path}",
            "tmuxgate MCP listening on "
            f"http://{config.mcp.host}:{config.mcp.port}/mcp",
            "Configured machines: " + ", ".join(config.machines),
            f"Approval mode: {config.broker.approval_mode}",
            f"MCP bearer token file: {token_path}",
        )
        for message in messages:
            operator.publish_activity(
                OperationalActivity.create(ActivityKind.STARTUP, message)
            )
        if config.broker.approval_mode == "disabled":
            operator.publish_activity(
                OperationalActivity.create(
                    ActivityKind.WARNING,
                    "WARNING: authenticated requests run without per-command approval.",
                )
            )


__all__ = ["RecoveryBlockedError", "UnifiedApplication"]
