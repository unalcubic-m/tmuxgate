"""One-process lifecycle for the broker, MCP server, and terminal dashboard."""

from __future__ import annotations

from contextlib import ExitStack
import getpass
from pathlib import Path
import signal
import threading
from typing import Callable

from tmuxgate.approval import ApprovalDecision, open_approval_terminal
from tmuxgate.automatic_recovery import AutomaticRecoveryCoordinator
from tmuxgate.availability import MachineAvailabilityRegistry
from tmuxgate.broker import BrokerServer
from tmuxgate.broker_api import BrokerControlService
from tmuxgate.config import AppConfig, Machine, load_config
from tmuxgate.connection_plan import ConnectionPlan
from tmuxgate.credentials import SudoCredentialStore
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
    resolve_operator_prompt,
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
from tmuxgate.reboot_recovery import RealBootIdProbe
from tmuxgate.recovery_coordinator import ExpectedRebootRecoveryCoordinator
from tmuxgate.runtime import (
    acquire_runtime_ownership,
    load_or_create_mcp_token,
    open_broker_listener,
    prepare_runtime_layout,
)
from tmuxgate.spool import ResultSpool
from tmuxgate.settings import set_approval_mode, set_machine_enabled
from tmuxgate.scheduler import RequestState
from tmuxgate.ssh import ResolvedSshEndpoint, resolve_ssh_endpoint
from tmuxgate.ssh_key import AutoSshKeyManager
from tmuxgate.state import DurableStateStore, RemotePhase, recover_startup
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


def _enroll_sudo_credential(
    operator: OperatorInterface,
    store: SudoCredentialStore,
    machine_name: str,
    prompt: bytes,
    *,
    password_reader: Callable[..., str] = getpass.getpass,
    terminal_opener: Callable[..., object] = open_approval_terminal,
) -> bytes | None:
    """Collect and persist one first-use password and exact machine prompt."""

    if not isinstance(machine_name, str) or not isinstance(prompt, bytes):
        raise TypeError("sudo credential enrollment identity is invalid")
    if b"sudo" in prompt.lower():
        stored = store.set_prompt(machine_name, prompt)
        if stored is not None:
            return stored
    enrolled: list[bytes] = []

    def session() -> None:
        with terminal_opener() as terminal:
            terminal.writer.write(
                "\n[tmuxgate] First-use sudo setup\n"
                f"Machine: {machine_name}\n"
                f"Detected exact prompt: {prompt!r}\n"
                "Entering a password trusts this exact prompt for this machine, "
                "submits it now, and saves both for future automatic use.\n"
                "Leave it empty to cancel. The password is hidden: "
            )
            terminal.writer.flush()
            try:
                password = password_reader("", stream=terminal.writer)
            except (EOFError, KeyboardInterrupt):
                terminal.writer.write("\nSudo setup cancelled.\n")
                terminal.writer.flush()
                return
            if not password:
                terminal.writer.write("Sudo setup cancelled.\n")
                terminal.writer.flush()
                return
            store.set_credential(machine_name, password, prompt)
            enrolled.append(password.encode("utf-8"))
            terminal.writer.write(
                "Sudo password and exact prompt saved; continuing automatically.\n"
            )
            terminal.writer.flush()

    operator.run_terminal_session(
        f"first-use sudo setup for {machine_name}",
        session,
    )
    return enrolled[0] if enrolled else None


class _ZeroFakeExecutor:
    def __call__(self, request_id: str, request: RequestSpec) -> FakeExecution:
        del request_id, request
        return FakeExecution()


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
        clean = True
        operator: OperatorInterface
        pool: MasterTransportPool | None = None
        prompt_presenter: SecretPromptPresenter | None = None
        automatic_coordinator: AutomaticRecoveryCoordinator | None = None
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
            # Both locks precede token/state/spool access, operator activation,
            # stale-master reconciliation, and every work-accepting listener.
            ownership = resources.enter_context(acquire_runtime_ownership(paths))
            for message in ownership.reconciled:
                print(f"tmuxgate: {message}")
            bearer_token = load_or_create_mcp_token(paths.state_dir)
            credential_store = SudoCredentialStore(paths.state_dir)
            if self._operator_interface is not None:
                operator = self._operator_interface
            elif self._textual:
                operator = TextualOperatorInterface(
                    self._terminal,
                    approval_mode=config.broker.approval_mode,
                    credential_store=credential_store,
                )
            else:
                operator = PlainTerminalInterface(
                    self._terminal,
                    dashboard=self._dashboard,
                    approval_mode=config.broker.approval_mode,
                )
            if isinstance(operator, TextualOperatorInterface):
                def set_automatic_mode(enabled: bool) -> str:
                    mode = "disabled" if enabled else "always"
                    set_approval_mode(self._config_path, mode)
                    return mode

                operator.bind_automation_setter(set_automatic_mode)
            resources.callback(close_operator)
            store = resources.enter_context(DurableStateStore(paths.state_dir))
            spool = resources.enter_context(ResultSpool(paths.state_dir))
            recovery = recover_startup(store)
            if not recovery.safe_to_accept_new_approvals:
                blocked = ", ".join(recovery.blocking_request_ids)
                raise RecoveryBlockedError(
                    f"recovery blocks new approvals: {blocked}"
                )
            if self._fake:
                def approver(request_id: str, request: RequestSpec) -> ApprovalDecision:
                    prompt = ExecutionApprovalPrompt.create(
                        request_id,
                        request,
                        None,
                        unbound_fake=True,
                    )
                    return require_operator_decision(
                        prompt,
                        resolve_operator_prompt(operator, prompt),
                    )
                selected_executor = _ZeroFakeExecutor()
                def approval_discarder(request_id: str) -> None:
                    return None

                def delivery_observer(request_id: str, delivered: bool) -> None:
                    return None
            else:
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
                        resolve_operator_prompt(operator, prompt),
                    )

                planner = BoundRequestPlanner(
                    config,
                    approver=bound_approver,
                    machine_enabled=availability.is_enabled,
                )

                def approver(request_id: str, request: RequestSpec) -> ApprovalDecision:
                    return planner(request_id, request)

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
                    backend=SubprocessMasterBackend(
                        terminal_lock=self._terminal,
                        terminal_handoff=operator.run_terminal_session,
                    ),
                    identity_revalidator=revalidate,
                    max_masters=config.broker.max_open_ssh_masters,
                    idle_timeout_seconds=(
                        config.broker.ssh_master_idle_timeout_seconds
                    ),
                    key_manager=AutoSshKeyManager(),
                )
                startup_endpoints = tuple(
                    resolve_ssh_endpoint(machine, endpoint)
                    for machine in config.machines.values()
                    for endpoint in machine.endpoints
                )
                expected_reboot_records = tuple(
                    record
                    for record in recovery.records
                    if record.request_id in recovery.expected_reboot_request_ids
                )
                automatic_records = tuple(
                    record
                    for record in recovery.records
                    if record.request_id in recovery.automatic_recovery_request_ids
                )
                protected_paths = tuple(
                    pool.expected_control_path(
                        record.machine_alias,
                        record.resolved_identity_sha256,
                    )
                    for record in expected_reboot_records + automatic_records
                    if record.resolved_identity_sha256 is not None
                )
                for reconciled_path in pool.reconcile_startup(
                    startup_endpoints,
                    protected_paths=protected_paths,
                ):
                    print(
                        "tmuxgate: reconciled stale SSH control socket "
                        f"{reconciled_path}"
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
                    authorizer=lambda prompt: resolve_operator_prompt(
                        operator, prompt
                    ),
                    secret_provider=credential_store.password_for,
                    prompt_provider=credential_store.prompt_for,
                    credential_enroller=lambda machine, prompt: (
                        _enroll_sudo_credential(
                            operator,
                            credential_store,
                            machine,
                            prompt,
                        )
                    ),
                    automatic_secret_input=lambda: (
                        getattr(
                            operator,
                            "approval_mode",
                            config.broker.approval_mode,
                        )
                        == "disabled"
                    ),
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
                reboot_coordinator = ExpectedRebootRecoveryCoordinator(
                    state=store,
                    transports=pool,
                    boot_id_probe=RealBootIdProbe(channels),
                    identity_revalidator=revalidate,
                    timeout_seconds=config.broker.reboot_recovery_timeout_seconds,
                )
                reboot_coordinator.register_startup(recovery.records)
                recovery_threads: list[threading.Thread] = []

                def resume_expected_reboot(
                    record,
                    endpoint: ResolvedSshEndpoint,
                ) -> None:
                    try:
                        result = reboot_coordinator.recover(record, endpoint)
                        operator.publish_activity(
                            OperationalActivity.create(
                                ActivityKind.STATUS,
                                (
                                    "Expected reboot recovery finished with "
                                    f"{result.transport_status.value}."
                                ),
                                request_id=record.request_id,
                                machine_name=record.machine_alias,
                                endpoint_id=record.endpoint_id,
                            )
                        )
                    except BaseException as exc:
                        operator.publish_activity(
                            OperationalActivity.create(
                                ActivityKind.ERROR,
                                f"Expected reboot recovery failed closed: {exc}",
                                request_id=record.request_id,
                                machine_name=record.machine_alias,
                                endpoint_id=record.endpoint_id,
                            )
                        )

                for record in expected_reboot_records:
                    endpoint = next(
                        (
                            item
                            for item in startup_endpoints
                            if item.machine_name == record.machine_alias
                            and item.endpoint_id == record.endpoint_id
                        ),
                        None,
                    )
                    if endpoint is None:
                        operator.publish_activity(
                            OperationalActivity.create(
                                ActivityKind.ERROR,
                                "Expected reboot recovery has no matching configured endpoint.",
                                request_id=record.request_id,
                                machine_name=record.machine_alias,
                                endpoint_id=record.endpoint_id,
                            )
                        )
                        continue
                    thread = threading.Thread(
                        target=resume_expected_reboot,
                        args=(record, endpoint),
                        name=f"tmuxgate-reboot-{record.request_id[:8]}",
                        daemon=True,
                    )
                    recovery_threads.append(thread)
                    thread.start()

                def close_reboot_coordinator() -> None:
                    reboot_coordinator.close()
                    for thread in recovery_threads:
                        thread.join(timeout=5)
                        if thread.is_alive():
                            owned_components_clean[0] = False
                            report_error(
                                "tmuxgate: expected reboot recovery worker did not stop"
                            )

                resources.callback(close_reboot_coordinator)
                collection_dir = prepare_collection_directory(
                    paths.state_dir / "collections"
                )
                collection_budget = LocalCollectionBudget(
                    config.limits.max_aggregate_collection_bytes
                )

                automatic_coordinator = AutomaticRecoveryCoordinator(
                    state=store,
                    spool=spool,
                    transports=pool,
                    backend_factory=lambda transport: RealRemoteJobBackend(
                        transport,
                        channels=channels,
                        viewer_dir=paths.viewer_dir,
                        collection_dir=collection_dir,
                        limits=config.limits,
                        collection_budget=collection_budget,
                        recover_existing_viewer=True,
                    ),
                )
                automatic_stop = threading.Event()
                automatic_status: dict[str, str] = {}

                def reconcile_ordinary_jobs() -> None:
                    while not automatic_stop.is_set():
                        pending_cleanup = tuple(
                            record.request_id
                            for record in store.load_all()
                            if record.remote_phase
                            is RemotePhase.RESULT_SPOOL_LOCALLY_VERIFIED
                        )
                        request_ids = tuple(
                            dict.fromkeys(
                                recovery.automatic_recovery_request_ids
                                + pending_cleanup
                            )
                        )
                        for request_id in request_ids:
                            if automatic_stop.is_set():
                                break
                            try:
                                record = store.load(request_id)
                                endpoint = next(
                                    (
                                        item
                                        for item in startup_endpoints
                                        if item.machine_name == record.machine_alias
                                        and item.endpoint_id == record.endpoint_id
                                    ),
                                    None,
                                )
                                if endpoint is None:
                                    raise RuntimeError(
                                        "durable recovery endpoint is no longer configured"
                                    )
                                outcome = automatic_coordinator.reconcile(
                                    record, endpoint
                                )
                                status_key = outcome.status + "\0" + outcome.detail
                                if automatic_status.get(request_id) != status_key:
                                    automatic_status[request_id] = status_key
                                    operator.publish_activity(
                                        OperationalActivity.create(
                                            (
                                                ActivityKind.ERROR
                                                if outcome.manual_action_required
                                                else ActivityKind.STATUS
                                            ),
                                            "Automatic recovery: " + outcome.detail,
                                            request_id=request_id,
                                            machine_name=record.machine_alias,
                                            endpoint_id=record.endpoint_id,
                                        )
                                    )
                                if outcome.status in {
                                    "failed-pre-remote",
                                    "failed-remote-setup",
                                    "recovered",
                                    "result-recovered-cleanup-pending",
                                    "no-action",
                                }:
                                    reboot_coordinator.release_claim(
                                        record.machine_alias, request_id
                                    )
                            except BaseException as exc:
                                detail = f"automatic recovery will retry safely: {exc}"
                                if automatic_status.get(request_id) != detail:
                                    automatic_status[request_id] = detail
                                    operator.publish_activity(
                                        OperationalActivity.create(
                                            ActivityKind.ERROR,
                                            detail,
                                            request_id=request_id,
                                        )
                                    )
                        automatic_stop.wait(1.0)

                automatic_thread = threading.Thread(
                    target=reconcile_ordinary_jobs,
                    name="tmuxgate-automatic-recovery",
                    daemon=True,
                )
                automatic_thread.start()

                def close_automatic_coordinator() -> None:
                    automatic_stop.set()
                    automatic_thread.join(timeout=5)
                    if automatic_thread.is_alive():
                        owned_components_clean[0] = False
                        report_error(
                            "tmuxgate: automatic recovery worker did not stop"
                        )
                    automatic_coordinator.close()

                resources.callback(close_automatic_coordinator)

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
                    reboot_recovery=reboot_coordinator,
                )
                selected_executor = executor
                approval_discarder = executor.discard_approval
                delivery_observer = executor.result_delivery_finished

            lifecycle = resources.enter_context(
                open_broker_listener(
                    paths.socket_path,
                    existing_lock=ownership.runtime_lock,
                )
            )
            control_service = BrokerControlService(
                config.machines,
                store,
                spool,
                machine_enabled=availability.is_enabled,
                runtime_owner=ownership.state_lock.owner,
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
                external_active_count=(
                    (lambda: 0)
                    if self._fake
                    else (
                        lambda: reboot_coordinator.active_count
                        + (
                            automatic_coordinator.active_count
                            if automatic_coordinator is not None
                            else 0
                        )
                    )
                ),
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
                    RequestState.ABANDONED_AFTER_OPERATOR_ACKNOWLEDGED_UNCERTAINTY,
                    RequestState.ABANDONED_AFTER_PROVEN_UNSTARTED,
                    RequestState.ABANDONED_AFTER_VERIFIED_REBOOT,
                    RequestState.DONE,
                }

                def dashboard_snapshot() -> DashboardRuntimeSnapshot:
                    retained = set(pool.retained_machine_names) if pool else set()
                    records = store.load_all()
                    def dashboard_job(record) -> DashboardJob:
                        manual = (
                            record.state
                            is RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING
                            and (
                                record.remote_phase.value == "legacy_uncertain"
                                or (
                                    record.failure_detail is not None
                                    and "neither a complete authenticated result"
                                    in record.failure_detail
                                )
                            )
                        )
                        return DashboardJob(
                            request_id=record.request_id,
                            machine_alias=record.machine_alias,
                            state=record.state.value,
                            updated_at=record.updated_at,
                            active=record.state not in terminal_states,
                            manual_action_required=manual,
                            recovery_evidence=(
                                "phase="
                                + record.remote_phase.value
                                + "; "
                                + (record.failure_detail or "no additional evidence")
                                if manual
                                else ""
                            ),
                        )

                    jobs = tuple(dashboard_job(record) for record in records[-100:])
                    machines = tuple(
                        DashboardMachine(
                            alias=name,
                            description=machine.description,
                            enabled=availability.is_enabled(name),
                            sudo_password=credential_store.has_password(name),
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
                    terminal = self._terminal.state
                    owner = (
                        terminal.purpose or "external terminal user"
                        if terminal.busy
                        else operator.terminal_ownership_state.value
                    )
                    return DashboardRuntimeSnapshot(
                        ready=(
                            services_ready[0]
                            and not (
                                operator.approval_mode == "disabled"
                                and operator.pending_prompt_count > 0
                            )
                        ),
                        listener=f"http://{config.mcp.host}:{config.mcp.port}/mcp",
                        approval_mode=operator.approval_mode,
                        machines=machines,
                        jobs=jobs,
                        active_job_count=sum(
                            record.state not in terminal_states for record in records
                        ),
                        terminal_owner=owner,
                    )

                operator.bind_dashboard_provider(dashboard_snapshot)

                def acknowledge_uncertainty(request_id: str) -> str:
                    record = store.load(request_id)
                    manual = (
                        record.state
                        is RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING
                        and (
                            record.remote_phase.value == "legacy_uncertain"
                            or (
                                record.failure_detail is not None
                                and "neither a complete authenticated result"
                                in record.failure_detail
                            )
                        )
                    )
                    if not manual:
                        raise RuntimeError(
                            "request no longer requires the uncertainty action"
                        )
                    abandoned = (
                        store.mark_abandoned_after_operator_acknowledged_uncertainty(
                            record
                        )
                    )
                    if not self._fake:
                        reboot_coordinator.release_claim(
                            abandoned.machine_alias, abandoned.request_id
                        )
                    return abandoned.state.value

                operator.bind_recovery_acknowledger(acknowledge_uncertainty)
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
                    ActivityKind.STARTUP,
                    "Automation is on: Codex approval is sufficient for execution.",
                )
            )


__all__ = ["RecoveryBlockedError", "UnifiedApplication"]
