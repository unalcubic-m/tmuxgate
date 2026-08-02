"""One-shot approval-bound request planning with no remote connection."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import threading

from tmuxgate.approval import ApprovalDecision
from tmuxgate.config import AppConfig
from tmuxgate.connection_plan import (
    ConnectionPlan,
    build_connection_plan,
)
from tmuxgate.models import RequestSpec, validate_request_id
from tmuxgate.network import NetworkSnapshot, RoutePlan, build_route_plan
from tmuxgate.network_collect import collect_network_snapshot
from tmuxgate.ssh import resolve_ssh_endpoint


class PlanningError(RuntimeError):
    """A request could not receive or consume an exact bound plan."""


SnapshotCollector = Callable[..., NetworkSnapshot]
RouteBuilder = Callable[..., RoutePlan]
ConnectionBuilder = Callable[..., ConnectionPlan]
BoundApprover = Callable[..., ApprovalDecision]
MachineEnabled = Callable[[str], bool]


def _candidate_retry_semantics(plan: ConnectionPlan) -> tuple[tuple[object, ...], ...]:
    """Return ordered route-candidate fields that affect retry eligibility."""

    return tuple(
        (
            candidate.endpoint_id,
            candidate.address,
            candidate.port,
            candidate.required_context,
            candidate.priority,
            candidate.result,
        )
        for candidate in plan.candidates
    )


def _retry_semantics_match(expected: ConnectionPlan, current: ConnectionPlan) -> bool:
    """Compare security semantics while ignoring volatile observation bytes."""

    return (
        current.machine_name == expected.machine_name
        and current.fallback_policy == expected.fallback_policy
        and _candidate_retry_semantics(current)
        == _candidate_retry_semantics(expected)
        and current.endpoints == expected.endpoints
    )


@dataclass(frozen=True, slots=True)
class ApprovedRequestContext:
    request_id: str
    request_sha256: str
    connection_plan: ConnectionPlan

    def __post_init__(self) -> None:
        validate_request_id(self.request_id)
        if (
            not isinstance(self.request_sha256, str)
            or len(self.request_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.request_sha256)
        ):
            raise ValueError("approved request digest is invalid")
        if not isinstance(self.connection_plan, ConnectionPlan):
            raise TypeError("connection_plan must be a ConnectionPlan")


class BoundRequestPlanner:
    """Create and consume exactly one immutable post-approval plan.

    The planner stores only the request digest and connection plan.  It does not
    retain script bytes, start a master transport, or mutate a remote host.
    """

    def __init__(
        self,
        config: AppConfig,
        *,
        snapshot_collector: SnapshotCollector = collect_network_snapshot,
        route_builder: RouteBuilder = build_route_plan,
        connection_builder: ConnectionBuilder = build_connection_plan,
        endpoint_resolver: Callable[..., object] = resolve_ssh_endpoint,
        approver: BoundApprover | None = None,
        machine_enabled: MachineEnabled | None = None,
    ) -> None:
        if not isinstance(config, AppConfig):
            raise TypeError("config must be an AppConfig")
        for name, callback in (
            ("snapshot_collector", snapshot_collector),
            ("route_builder", route_builder),
            ("connection_builder", connection_builder),
            ("endpoint_resolver", endpoint_resolver),
        ):
            if not callable(callback):
                raise TypeError(f"{name} must be callable")
        if not callable(approver):
            raise TypeError("approver must be provided by the operator boundary")
        self.config = config
        self.snapshot_collector = snapshot_collector
        self.route_builder = route_builder
        self.connection_builder = connection_builder
        self.endpoint_resolver = endpoint_resolver
        self.approver: BoundApprover = approver
        self.machine_enabled = (
            (lambda alias: config.machines[alias].enabled)
            if machine_enabled is None
            else machine_enabled
        )
        if not callable(self.machine_enabled):
            raise TypeError("machine_enabled must be callable")
        self._approved: dict[str, ApprovedRequestContext] = {}
        self._planning_request_id: str | None = None
        self._lock = threading.Lock()

    @property
    def pending_request_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._approved))

    def _build_connection_plan(self, request: RequestSpec) -> ConnectionPlan:
        if not isinstance(request, RequestSpec):
            raise TypeError("request must be a RequestSpec")
        try:
            machine = self.config.machines[request.machine_alias]
        except KeyError as exc:
            raise PlanningError(
                f"unknown configured machine: {request.machine_alias}"
            ) from exc
        self._require_machine_enabled(request.machine_alias, machine.enabled)
        destinations = tuple(endpoint.address for endpoint in machine.endpoints)
        snapshot = self.snapshot_collector(
            destinations,
            home_gateway=(
                None if self.config.home is None else self.config.home.gateway
            ),
        )
        if not isinstance(snapshot, NetworkSnapshot):
            raise PlanningError("snapshot collector returned an invalid object")
        route_plan = self.route_builder(
            machine,
            snapshot,
            self.config.home,
            self.config.wireguard,
        )
        if not isinstance(route_plan, RoutePlan):
            raise PlanningError("route builder returned an invalid object")
        connection_plan = self.connection_builder(
            route_plan,
            snapshot,
            resolver=self.endpoint_resolver,
        )
        if not isinstance(connection_plan, ConnectionPlan):
            raise PlanningError("connection builder returned an invalid object")
        return connection_plan

    def _require_machine_enabled(
        self,
        machine_name: str,
        configured_enabled: bool = True,
    ) -> None:
        try:
            runtime_enabled = self.machine_enabled(machine_name)
        except BaseException as exc:
            raise PlanningError("machine availability could not be verified") from exc
        if type(runtime_enabled) is not bool:
            raise PlanningError("machine availability callback returned invalid state")
        if not configured_enabled or not runtime_enabled:
            raise PlanningError(f"configured machine is disabled: {machine_name}")

    def _begin_planning(self, request_id: str) -> None:
        with self._lock:
            if self._planning_request_id is not None:
                raise PlanningError("another request is currently being planned")
            self._planning_request_id = request_id

    def _finish_planning(self, request_id: str) -> None:
        with self._lock:
            if self._planning_request_id == request_id:
                self._planning_request_id = None

    def __call__(self, request_id: str, request: RequestSpec) -> ApprovalDecision:
        request_id = validate_request_id(request_id)
        if not isinstance(request, RequestSpec):
            raise TypeError("request must be a RequestSpec")
        self._begin_planning(request_id)
        try:
            connection_plan = self._build_connection_plan(request)
            decision = ApprovalDecision(
                self.approver(request_id, request, connection_plan)
            )
            if decision is ApprovalDecision.DENIED:
                return decision
            if decision is not ApprovalDecision.APPROVED:
                raise PlanningError("approval callback returned an invalid decision")
            self._require_machine_enabled(request.machine_alias)
            context = ApprovedRequestContext(
                request_id,
                request.client_request_sha256(),
                connection_plan,
            )
            with self._lock:
                if request_id in self._approved:
                    raise PlanningError("approved request context already exists")
                self._approved[request_id] = context
            return decision
        finally:
            self._finish_planning(request_id)

    def revalidate_connection_plan(
        self,
        request_id: str,
        request: RequestSpec,
        expected: ConnectionPlan,
        *,
        retried_endpoint_id: str,
    ) -> ConnectionPlan:
        """Re-prove stable route and SSH semantics before a pre-remote retry."""

        request_id = validate_request_id(request_id)
        if not isinstance(request, RequestSpec):
            raise TypeError("request must be a RequestSpec")
        if not isinstance(expected, ConnectionPlan):
            raise TypeError("expected must be a ConnectionPlan")
        if not isinstance(retried_endpoint_id, str):
            raise TypeError("retried_endpoint_id must be a string")
        if not retried_endpoint_id:
            raise ValueError("retried_endpoint_id must not be empty")
        if expected.machine_name != request.machine_alias:
            raise PlanningError("retry plan belongs to a different machine")
        approved_endpoint_ids = tuple(
            endpoint.resolved.endpoint_id for endpoint in expected.endpoints
        )
        if retried_endpoint_id not in approved_endpoint_ids:
            raise PlanningError("retry endpoint was not eligible in the approved plan")
        self._begin_planning(request_id)
        try:
            current = self._build_connection_plan(request)
        finally:
            self._finish_planning(request_id)
        current_endpoint_ids = tuple(
            endpoint.resolved.endpoint_id for endpoint in current.endpoints
        )
        if retried_endpoint_id not in current_endpoint_ids:
            raise PlanningError(
                "retry endpoint is no longer eligible; submit a fresh request "
                "for a new approval"
            )
        if not _retry_semantics_match(expected, current):
            raise PlanningError(
                "approved route or SSH plan changed before retry; submit a fresh "
                "request for a new approval"
            )
        return current

    def take(
        self,
        request_id: str,
        request: RequestSpec,
    ) -> ApprovedRequestContext:
        request_id = validate_request_id(request_id)
        if not isinstance(request, RequestSpec):
            raise TypeError("request must be a RequestSpec")
        with self._lock:
            context = self._approved.get(request_id)
            if context is None:
                raise PlanningError("no approved plan exists for this request")
            if context.request_sha256 != request.client_request_sha256():
                raise PlanningError("approved plan belongs to different request bytes")
            if context.connection_plan.machine_name != request.machine_alias:
                raise PlanningError("approved plan belongs to a different machine")
            try:
                self._require_machine_enabled(request.machine_alias)
            except BaseException:
                del self._approved[request_id]
                raise
            del self._approved[request_id]
        return context

    def discard(self, request_id: str) -> bool:
        request_id = validate_request_id(request_id)
        with self._lock:
            return self._approved.pop(request_id, None) is not None
