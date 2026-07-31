"""Pure route-policy evaluation over an injected local network snapshot."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import ipaddress
import uuid
from typing import Mapping

from tmuxgate.config import Endpoint, HomeContext, Machine, WireGuardContext


class EvidenceResult(StrEnum):
    MATCH = "match"
    NO_MATCH = "no_match"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RouteObservation:
    destination: ipaddress.IPv4Address
    interface: str
    source: ipaddress.IPv4Address | None
    gateway: ipaddress.IPv4Address | None


@dataclass(frozen=True, slots=True)
class NeighborObservation:
    mac: str
    state: str


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    addresses_by_interface: Mapping[str, tuple[ipaddress.IPv4Interface, ...]]
    link_flags: Mapping[str, frozenset[str]]
    link_types: Mapping[str, str]
    routes: Mapping[ipaddress.IPv4Address, RouteObservation]
    neighbors: Mapping[tuple[str, ipaddress.IPv4Address], NeighborObservation]
    connection_uuid_by_interface: Mapping[str, uuid.UUID]
    bssid_by_interface: Mapping[str, str]
    collection_errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    endpoint: Endpoint
    result: EvidenceResult
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RoutePlan:
    machine: Machine
    candidates: tuple[CandidateEvaluation, ...]
    eligible: tuple[Endpoint, ...]

    @property
    def selected(self) -> Endpoint | None:
        return self.eligible[0] if self.eligible else None


def _assigned(snapshot: NetworkSnapshot, interface: str, source: ipaddress.IPv4Address) -> bool:
    return any(item.ip == source for item in snapshot.addresses_by_interface.get(interface, ()))


def _route_for(
    snapshot: NetworkSnapshot,
    destination: ipaddress.IPv4Address,
) -> tuple[RouteObservation | None, str | None]:
    route = snapshot.routes.get(destination)
    if route is None:
        return None, "route evidence is missing"
    if route.destination != destination:
        return None, "route observation destination does not match its key"
    return route, None


def evaluate_home(
    context: HomeContext,
    endpoint: Endpoint,
    snapshot: NetworkSnapshot,
) -> CandidateEvaluation:
    if not isinstance(endpoint.address, ipaddress.IPv4Address):
        return CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, ("home endpoint is not IPv4",))
    gateway_route, gateway_error = _route_for(snapshot, context.gateway)
    endpoint_route, endpoint_error = _route_for(snapshot, endpoint.address)
    if gateway_route is None or endpoint_route is None:
        details = tuple(
            detail
            for detail in (gateway_error, endpoint_error)
            if detail is not None
        )
        return CandidateEvaluation(endpoint, EvidenceResult.UNKNOWN, details)
    reasons: list[str] = []
    if gateway_route.gateway is not None:
        reasons.append("home gateway route is not directly connected")
    if gateway_route.source is None or gateway_route.source not in context.source_cidr:
        reasons.append("selected source is outside the home subnet")
    elif not _assigned(snapshot, gateway_route.interface, gateway_route.source):
        reasons.append("selected source is not assigned to the route interface")
    if endpoint_route.gateway is not None:
        reasons.append("home endpoint route is not directly connected")
    if endpoint_route.interface != gateway_route.interface:
        reasons.append("home gateway and endpoint use different interfaces")
    if endpoint_route.source != gateway_route.source:
        reasons.append("home gateway and endpoint use different source addresses")
    if reasons:
        return CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, tuple(reasons))
    interface_flags = snapshot.link_flags.get(gateway_route.interface)
    if interface_flags is None:
        return CandidateEvaluation(endpoint, EvidenceResult.UNKNOWN, ("home interface flags are missing",))
    if "UP" not in interface_flags:
        return CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, ("home interface is not UP",))
    if not context.fingerprints:
        return CandidateEvaluation(endpoint, EvidenceResult.UNKNOWN, ("no enrolled home fingerprint",))

    interface = gateway_route.interface
    observed_link = snapshot.link_types.get(interface)
    observed_neighbor = snapshot.neighbors.get((interface, context.gateway))
    observed_uuid = snapshot.connection_uuid_by_interface.get(interface)
    observed_bssid = snapshot.bssid_by_interface.get(interface)
    saw_unknown = False
    mismatch_reasons: list[str] = []
    for fingerprint in context.fingerprints:
        missing: list[str] = []
        mismatches: list[str] = []
        if observed_link is None:
            missing.append("link type")
        elif observed_link != fingerprint.link_type:
            mismatches.append("link type")
        elif fingerprint.link_type == "ethernet" and "LOWER_UP" not in interface_flags:
            # IFF_UP proves only administrative state.  IFF_LOWER_UP is the
            # current kernel carrier indication and prevents an old address,
            # route, UUID, and STALE neighbor entry from identifying "home"
            # after a cable has been unplugged.
            mismatches.append("Ethernet carrier")
        if observed_neighbor is None:
            missing.append("gateway neighbor")
        elif observed_neighbor.state.upper() not in {
            "REACHABLE",
            "STALE",
            "DELAY",
            "PROBE",
            "PERMANENT",
        }:
            mismatches.append("gateway neighbor state")
        elif observed_neighbor.mac.lower() not in fingerprint.gateway_macs:
            mismatches.append("gateway MAC")
        if observed_uuid is None:
            missing.append("connection UUID")
        elif observed_uuid not in fingerprint.connection_uuids:
            mismatches.append("connection UUID")
        if fingerprint.link_type == "wifi":
            if observed_bssid is None:
                # The BSSID is also the current association evidence for a
                # Wi-Fi fingerprint; an administratively UP interface is not
                # sufficient by itself.
                missing.append("current Wi-Fi association BSSID")
            elif observed_bssid.lower() not in fingerprint.bssids:
                mismatches.append("current Wi-Fi association BSSID")
        if not missing and not mismatches:
            return CandidateEvaluation(
                endpoint,
                EvidenceResult.MATCH,
                (f"home fingerprint {fingerprint.id} matched",),
            )
        if missing:
            saw_unknown = True
        mismatch_reasons.append(
            f"fingerprint {fingerprint.id}: "
            + ", ".join([*(f"missing {item}" for item in missing), *(f"mismatched {item}" for item in mismatches)])
        )
    result = EvidenceResult.UNKNOWN if saw_unknown else EvidenceResult.NO_MATCH
    return CandidateEvaluation(endpoint, result, tuple(mismatch_reasons))


def evaluate_wireguard(
    context: WireGuardContext,
    endpoint: Endpoint,
    snapshot: NetworkSnapshot,
) -> CandidateEvaluation:
    if not isinstance(endpoint.address, ipaddress.IPv4Address):
        return CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, ("WireGuard endpoint is not IPv4",))
    if not any(endpoint.address in network for network in context.remote_cidrs):
        return CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, ("endpoint is outside allowed WireGuard CIDRs",))
    route, route_error = _route_for(snapshot, endpoint.address)
    if route is None:
        return CandidateEvaluation(endpoint, EvidenceResult.UNKNOWN, (route_error,))
    interface = route.interface
    link_type = snapshot.link_types.get(interface)
    if link_type is None:
        return CandidateEvaluation(
            endpoint,
            EvidenceResult.UNKNOWN,
            ("WireGuard interface link type is missing",),
        )
    if link_type != "wireguard":
        return CandidateEvaluation(
            endpoint,
            EvidenceResult.NO_MATCH,
            ("configured WireGuard interface has a non-WireGuard link type",),
        )
    flags = snapshot.link_flags.get(interface)
    if flags is None:
        return CandidateEvaluation(endpoint, EvidenceResult.UNKNOWN, ("WireGuard interface is missing",))
    if "UP" not in flags:
        return CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, ("WireGuard interface is not UP",))
    assigned = set(snapshot.addresses_by_interface.get(interface, ()))
    configured_and_assigned = set(context.local_addresses).intersection(assigned)
    if not configured_and_assigned:
        return CandidateEvaluation(
            endpoint,
            EvidenceResult.NO_MATCH,
            ("no exact configured WireGuard interface address is assigned",),
        )
    allowed_route_sources = {item.ip for item in configured_and_assigned}
    reasons: list[str] = []
    if route.source not in allowed_route_sources:
        reasons.append("endpoint route source is not an exact configured-and-assigned address")
    if reasons:
        return CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, tuple(reasons))
    return CandidateEvaluation(
        endpoint,
        EvidenceResult.MATCH,
        ("kernel-selected WireGuard link, exact source, and route matched",),
    )


def build_route_plan(
    machine: Machine,
    snapshot: NetworkSnapshot,
    home: HomeContext | None,
    wireguard: WireGuardContext | None,
) -> RoutePlan:
    evaluations: list[CandidateEvaluation] = []
    for endpoint in machine.endpoints:
        if endpoint.required_context == "home":
            evaluation = (
                CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, ("home context is not configured",))
                if home is None
                else evaluate_home(home, endpoint, snapshot)
            )
        elif endpoint.required_context == "wireguard":
            evaluation = (
                CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, ("WireGuard context is not configured",))
                if wireguard is None
                else evaluate_wireguard(wireguard, endpoint, snapshot)
            )
        else:  # Configuration validation prevents this; retain fail-closed behavior.
            evaluation = CandidateEvaluation(endpoint, EvidenceResult.NO_MATCH, ("unsupported endpoint context",))
        evaluations.append(evaluation)
    eligible = tuple(
        item.endpoint
        for item in sorted(
            evaluations,
            key=lambda item: (
                0 if item.endpoint.required_context == "home" else 1,
                item.endpoint.priority,
                item.endpoint.id,
            ),
        )
        if item.result is EvidenceResult.MATCH
    )
    return RoutePlan(machine, tuple(evaluations), eligible)
