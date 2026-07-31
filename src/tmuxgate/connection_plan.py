"""Immutable, approval-bound route and OpenSSH resolution plans."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json

from tmuxgate.network import NetworkSnapshot, RoutePlan
from tmuxgate.ssh import ResolvedSshEndpoint, resolve_ssh_endpoint


CONNECTION_PLAN_VERSION = 1
FALLBACK_POLICY = "new-terminal-ack-before-remote-mutation"


class ConnectionPlanError(RuntimeError):
    """A complete, safe connection plan could not be proven."""


EndpointResolver = Callable[..., ResolvedSshEndpoint]


def _canonical_sha256(document: Mapping[str, object]) -> str:
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def canonical_network_snapshot(snapshot: NetworkSnapshot) -> dict[str, object]:
    """Convert every route-decision input into deterministic JSON data."""

    return {
        "addresses_by_interface": {
            interface: sorted(str(item) for item in addresses)
            for interface, addresses in sorted(snapshot.addresses_by_interface.items())
        },
        "bssid_by_interface": dict(sorted(snapshot.bssid_by_interface.items())),
        "collection_errors": list(snapshot.collection_errors),
        "connection_uuid_by_interface": {
            interface: str(value)
            for interface, value in sorted(snapshot.connection_uuid_by_interface.items())
        },
        "link_flags": {
            interface: sorted(flags)
            for interface, flags in sorted(snapshot.link_flags.items())
        },
        "link_types": dict(sorted(snapshot.link_types.items())),
        "neighbors": [
            {
                "address": str(address),
                "interface": interface,
                "mac": observation.mac,
                "state": observation.state,
            }
            for (interface, address), observation in sorted(
                snapshot.neighbors.items(), key=lambda item: (item[0][0], int(item[0][1]))
            )
        ],
        "routes": [
            {
                "destination": str(destination),
                "gateway": (
                    None if observation.gateway is None else str(observation.gateway)
                ),
                "interface": observation.interface,
                "source": None if observation.source is None else str(observation.source),
            }
            for destination, observation in sorted(
                snapshot.routes.items(), key=lambda item: int(item[0])
            )
        ],
    }


@dataclass(frozen=True, slots=True)
class RouteCandidateRecord:
    endpoint_id: str
    address: str
    port: int
    required_context: str
    priority: int
    result: str
    reasons: tuple[str, ...]

    def canonical_document(self) -> dict[str, object]:
        return {
            "address": self.address,
            "endpoint_id": self.endpoint_id,
            "port": self.port,
            "priority": self.priority,
            "reasons": list(self.reasons),
            "required_context": self.required_context,
            "result": self.result,
        }


@dataclass(frozen=True, slots=True)
class PlannedEndpoint:
    route_index: int
    role: str
    resolved: ResolvedSshEndpoint

    def __post_init__(self) -> None:
        if type(self.route_index) is not int or self.route_index < 0:
            raise ValueError("route index must be a non-negative integer")
        expected_role = "selected" if self.route_index == 0 else "fallback"
        if self.role != expected_role:
            raise ValueError("planned endpoint role does not match its route index")

    def canonical_document(self) -> dict[str, object]:
        return {
            "resolved": self.resolved.canonical_document(),
            "role": self.role,
            "route_index": self.route_index,
        }


@dataclass(frozen=True, slots=True)
class ConnectionPlan:
    machine_name: str
    machine_description: str
    network_snapshot_sha256: str
    network_collection_errors: tuple[str, ...]
    candidates: tuple[RouteCandidateRecord, ...]
    endpoints: tuple[PlannedEndpoint, ...]
    fallback_policy: str
    plan_sha256: str

    def __post_init__(self) -> None:
        if not self.endpoints:
            raise ValueError("connection plan must contain a selected endpoint")
        if tuple(item.route_index for item in self.endpoints) != tuple(
            range(len(self.endpoints))
        ):
            raise ValueError("connection plan route indexes must be contiguous")
        if self.fallback_policy != FALLBACK_POLICY:
            raise ValueError("unsupported fallback policy")

    @property
    def selected(self) -> PlannedEndpoint:
        return self.endpoints[0]

    @property
    def fallbacks(self) -> tuple[PlannedEndpoint, ...]:
        return self.endpoints[1:]

    def canonical_document(self, *, include_digest: bool = True) -> dict[str, object]:
        document: dict[str, object] = {
            "candidates": [item.canonical_document() for item in self.candidates],
            "endpoints": [item.canonical_document() for item in self.endpoints],
            "fallback_policy": self.fallback_policy,
            "machine_description": self.machine_description,
            "machine_name": self.machine_name,
            "network_collection_errors": list(self.network_collection_errors),
            "network_snapshot_sha256": self.network_snapshot_sha256,
            "plan_version": CONNECTION_PLAN_VERSION,
        }
        if include_digest:
            document["plan_sha256"] = self.plan_sha256
        return document


def build_connection_plan(
    route_plan: RoutePlan,
    snapshot: NetworkSnapshot,
    *,
    resolver: EndpointResolver = resolve_ssh_endpoint,
) -> ConnectionPlan:
    """Resolve every eligible route before presenting any approval prompt.

    Failure to resolve even a later fallback fails the whole plan.  The broker
    must never silently omit or replace a fallback after the operator approved
    the displayed order.
    """

    if not isinstance(route_plan, RoutePlan):
        raise TypeError("route_plan must be a RoutePlan")
    if not isinstance(snapshot, NetworkSnapshot):
        raise TypeError("snapshot must be a NetworkSnapshot")
    if not route_plan.eligible:
        raise ConnectionPlanError("no strictly verified route is eligible")

    candidates = tuple(
        RouteCandidateRecord(
            endpoint_id=item.endpoint.id,
            address=item.endpoint.address.exploded,
            port=item.endpoint.port,
            required_context=item.endpoint.required_context,
            priority=item.endpoint.priority,
            result=item.result.value,
            reasons=item.reasons,
        )
        for item in route_plan.candidates
    )
    endpoints: list[PlannedEndpoint] = []
    for route_index, endpoint in enumerate(route_plan.eligible):
        try:
            resolved = resolver(route_plan.machine, endpoint)
        except Exception as exc:
            raise ConnectionPlanError(
                f"could not resolve eligible endpoint {endpoint.id!r}"
            ) from exc
        if not isinstance(resolved, ResolvedSshEndpoint):
            raise ConnectionPlanError("endpoint resolver returned an invalid result")
        required_matches = {
            "machine name": (resolved.machine_name, route_plan.machine.name),
            "endpoint ID": (resolved.endpoint_id, endpoint.id),
            "address": (resolved.configured_address, endpoint.address.exploded),
            "port": (resolved.configured_port, endpoint.port),
            "context": (resolved.required_context, endpoint.required_context),
        }
        for label, (observed, expected) in required_matches.items():
            if observed != expected:
                raise ConnectionPlanError(
                    f"resolved endpoint {label} does not match the route plan"
                )
        endpoints.append(
            PlannedEndpoint(
                route_index=route_index,
                role="selected" if route_index == 0 else "fallback",
                resolved=resolved,
            )
        )

    snapshot_document = canonical_network_snapshot(snapshot)
    snapshot_sha256 = _canonical_sha256(snapshot_document)
    provisional = ConnectionPlan(
        machine_name=route_plan.machine.name,
        machine_description=route_plan.machine.description,
        network_snapshot_sha256=snapshot_sha256,
        network_collection_errors=snapshot.collection_errors,
        candidates=candidates,
        endpoints=tuple(endpoints),
        fallback_policy=FALLBACK_POLICY,
        plan_sha256="",
    )
    digest = _canonical_sha256(provisional.canonical_document(include_digest=False))
    return ConnectionPlan(
        machine_name=provisional.machine_name,
        machine_description=provisional.machine_description,
        network_snapshot_sha256=provisional.network_snapshot_sha256,
        network_collection_errors=provisional.network_collection_errors,
        candidates=provisional.candidates,
        endpoints=provisional.endpoints,
        fallback_policy=provisional.fallback_policy,
        plan_sha256=digest,
    )
