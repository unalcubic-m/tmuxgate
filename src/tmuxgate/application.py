"""One-process lifecycle for the broker, MCP server, and terminal dashboard."""

from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import signal
import sys
import threading
from typing import Callable

from tmuxgate.approval import (
    ApprovalDecision,
    request_approval,
    request_fallback_approval,
    request_ssh_retry,
)
from tmuxgate.broker import BrokerServer
from tmuxgate.broker_api import BrokerControlService
from tmuxgate.config import AppConfig, load_config
from tmuxgate.executor import RealExecutor
from tmuxgate.fake import FakeExecution
from tmuxgate.mcp_server import (
    DEFAULT_CONTROL_WORKERS,
    BrokerCallPools,
    EmbeddedMcpServer,
    create_mcp_server,
)
from tmuxgate.models import RequestSpec
from tmuxgate.planning import BoundRequestPlanner
from tmuxgate.real_remote import RealRemoteJobBackend
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
from tmuxgate.ssh import ResolvedSshEndpoint, resolve_ssh_endpoint
from tmuxgate.ssh_key import AutoSshKeyManager
from tmuxgate.state import DurableStateStore, recover_startup
from tmuxgate.terminal import TerminalArbiter, TerminalPriority
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
    ) -> None:
        self._config_path = Path(config_path)
        self._socket_path = socket_path
        self._state_dir = state_dir
        self._fake = bool(fake)
        self._dashboard = dashboard
        self._terminal = TerminalArbiter() if terminal is None else terminal
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
        paths = prepare_runtime_layout(
            socket_path=self._socket_path,
            state_dir=self._state_dir,
        )
        bearer_token = load_or_create_mcp_token(paths.state_dir)
        clean = True
        pool: MasterTransportPool | None = None
        prompt_presenter: SecretPromptPresenter | None = None
        broker: BrokerServer | None = None
        mcp_http: EmbeddedMcpServer | None = None
        previous: dict[int, object] = {}
        owned_components_clean = [True]

        with ExitStack() as resources:
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
                        with self._terminal.claim(
                            priority=TerminalPriority.APPROVAL,
                            purpose="execution approval",
                        ):
                            return request_approval(request_id, request)
                else:
                    approver = _approve_without_prompt
                selected_executor = _ZeroFakeExecutor()
                approval_discarder = lambda request_id: None
                delivery_observer = lambda request_id, delivered: None
            else:
                if config.broker.approval_mode == "always":
                    planner = BoundRequestPlanner(config)

                    def approver(request_id: str, request: RequestSpec) -> ApprovalDecision:
                        with self._terminal.claim(
                            priority=TerminalPriority.APPROVAL,
                            purpose="execution approval",
                        ):
                            return planner(request_id, request)
                else:
                    planner = BoundRequestPlanner(
                        config,
                        approver=_approve_without_prompt,
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
                        print(
                            f"tmuxgate: could not close all idle SSH masters: {exc}",
                            file=sys.stderr,
                        )

                resources.callback(close_pool)
                prompt_presenter = SecretPromptPresenter(
                    terminal_lock=self._terminal,
                    reporter=lambda message: print(
                        f"tmuxgate: {message}", file=sys.stderr, flush=True
                    ),
                )

                def close_prompt_presenter() -> None:
                    assert prompt_presenter is not None
                    try:
                        if not prompt_presenter.close():
                            owned_components_clean[0] = False
                    except BaseException as exc:
                        owned_components_clean[0] = False
                        print(
                            f"tmuxgate: could not close the prompt presenter: {exc}",
                            file=sys.stderr,
                        )

                resources.callback(close_prompt_presenter)
                channels = SshChannelRunner(prompt_presenter=prompt_presenter)

                def fallback_approver(
                    *arguments: object,
                    **keywords: object,
                ) -> ApprovalDecision:
                    with self._terminal.claim(
                        priority=TerminalPriority.APPROVAL,
                        purpose="fallback approval",
                    ):
                        return request_fallback_approval(*arguments, **keywords)

                def ssh_retry_approver(
                    *arguments: object,
                    **keywords: object,
                ) -> ApprovalDecision:
                    with self._terminal.claim(
                        priority=TerminalPriority.SECRET,
                        purpose="SSH setup retry decision",
                    ):
                        return request_ssh_retry(*arguments, **keywords)

                executor = RealExecutor(
                    planner=planner,
                    transports=pool,
                    state=store,
                    spool=spool,
                    backend_factory=lambda transport: RealRemoteJobBackend(
                        transport,
                        channels=channels,
                        viewer_dir=paths.viewer_dir,
                    ),
                    fallback_approver=(
                        fallback_approver
                        if config.broker.approval_mode == "always"
                        else _approve_without_prompt
                    ),
                    ssh_retry_approver=ssh_retry_approver,
                )
                selected_executor = executor
                approval_discarder = executor.discard_approval
                delivery_observer = executor.result_delivery_finished

            control_service = BrokerControlService(config.machines, store, spool)
            run_worker_count = config.broker.max_pending_requests + 2
            control_worker_count = DEFAULT_CONTROL_WORKERS
            broker = BrokerServer(
                lifecycle.listener,
                allowed_machines=config.machines,
                approver=approver,
                executor=selected_executor,
                max_pending_requests=config.broker.max_pending_requests,
                max_active_remote_commands=config.broker.max_active_remote_commands,
                max_client_sessions=run_worker_count + control_worker_count,
                approval_discarder=approval_discarder,
                delivery_observer=delivery_observer,
                control_service=control_service,
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
            previous = self._install_signal_handlers()
            try:
                broker.start()
                mcp_http.start()
                self._report_started(config, paths.socket_path, paths.mcp_token_path)
                if self._dashboard is None:
                    while not self._stop.wait(0.25):
                        pass
                else:
                    self._dashboard(self._stop, self._terminal, config)
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
                        print(
                            f"tmuxgate: could not signal the MCP server: {exc}",
                            file=sys.stderr,
                        )
                if broker is not None:
                    try:
                        broker_clean = broker.stop()
                    except BaseException as exc:
                        broker_clean = False
                        print(
                            f"tmuxgate: could not stop the broker safely: {exc}",
                            file=sys.stderr,
                        )
                if mcp_http is not None:
                    try:
                        mcp_clean = mcp_http.stop() and mcp_clean
                    except BaseException as exc:
                        mcp_clean = False
                        print(
                            f"tmuxgate: could not stop the MCP server safely: {exc}",
                            file=sys.stderr,
                        )
                clean = broker_clean and mcp_clean and clean
                try:
                    self._restore_signal_handlers(previous)
                except BaseException as exc:
                    clean = False
                    print(
                        f"tmuxgate: could not restore signal handlers: {exc}",
                        file=sys.stderr,
                    )
                if not broker_clean or not mcp_clean:
                    # Live workers can still hold the state store, spool, SSH
                    # pool, or listener.  Closing those dependencies underneath
                    # them creates use-after-close races.  Keep ownership until
                    # the CLI process terminates and lets the OS reclaim it.
                    _RETAINED_SHUTDOWN_RESOURCES.append(resources.pop_all())
                    print(
                        "tmuxgate: shutdown incomplete; retaining owned resources "
                        "until process exit",
                        file=sys.stderr,
                    )
        clean = owned_components_clean[0] and clean
        return 0 if clean else EXIT_SOFTWARE

    def _report_started(
        self,
        config: AppConfig,
        socket_path: Path,
        token_path: Path,
    ) -> None:
        kind = "fake" if self._fake else "real"
        with self._terminal.claim(
            priority=TerminalPriority.DASHBOARD,
            purpose="startup status",
            flush_input=False,
        ):
            print(f"tmuxgate {kind} broker listening on {socket_path}")
            print(
                "tmuxgate MCP listening on "
                f"http://{config.mcp.host}:{config.mcp.port}/mcp"
            )
            print("Configured machines: " + ", ".join(config.machines))
            print(f"Approval mode: {config.broker.approval_mode}")
            print(f"MCP bearer token file: {token_path}")
            if config.broker.approval_mode == "disabled":
                print(
                    "WARNING: authenticated requests run without per-command approval."
                )


__all__ = ["RecoveryBlockedError", "UnifiedApplication"]
