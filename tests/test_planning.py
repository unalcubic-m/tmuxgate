import threading
import unittest

from tmuxgate.approval import ApprovalDecision
from tmuxgate.config import parse_config
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.network import NetworkSnapshot, RoutePlan
from tmuxgate.planning import (
    ApprovedRequestContext,
    BoundRequestPlanner,
    PlanningError,
)
from test_config import valid_config
from test_connection_plan import build_plan


REQUEST_ID = "0123456789abcdef0123456789abcdef"
SECOND_ID = "89abcdef0123456789abcdef01234567"


def empty_snapshot():
    return NetworkSnapshot({}, {}, {}, {}, {}, {}, {})


def request(argv=("printf", "hello")):
    return RequestSpec(
        machine_alias="app-server",
        mode=ExecutionMode.ARGV,
        cwd="/tmp",
        argv=argv,
    )


class PlannerHarness:
    def __init__(self, decision=ApprovalDecision.APPROVED):
        self.config = parse_config(valid_config())
        self.decision = decision
        self.snapshot_calls = []
        self.route_calls = []
        self.connection_calls = []
        self.approval_calls = []
        self.resolver = lambda *args, **kwargs: None

    def collect(self, destinations, *, home_gateway):
        self.snapshot_calls.append((tuple(destinations), home_gateway))
        return empty_snapshot()

    def route(self, machine, snapshot, home, wireguard):
        self.route_calls.append((machine, snapshot, home, wireguard))
        return RoutePlan(machine, (), (machine.endpoints[0],))

    def connect(self, route_plan, snapshot, *, resolver):
        self.connection_calls.append((route_plan, snapshot, resolver))
        return build_plan()

    def approve(self, request_id, spec, plan):
        self.approval_calls.append((request_id, spec, plan))
        return self.decision

    def planner(self):
        return BoundRequestPlanner(
            self.config,
            snapshot_collector=self.collect,
            route_builder=self.route,
            connection_builder=self.connect,
            endpoint_resolver=self.resolver,
            approver=self.approve,
        )


class BoundRequestPlannerTests(unittest.TestCase):
    def test_machine_name_builds_and_approves_complete_plan_without_remote_action(self):
        harness = PlannerHarness()
        planner = harness.planner()
        spec = request()

        decision = planner(REQUEST_ID, spec)

        self.assertEqual(decision, ApprovalDecision.APPROVED)
        self.assertEqual(planner.pending_request_ids, (REQUEST_ID,))
        destinations, gateway = harness.snapshot_calls[0]
        machine = harness.config.machines["app-server"]
        self.assertEqual(destinations, tuple(endpoint.address for endpoint in machine.endpoints))
        self.assertEqual(gateway, harness.config.home.gateway)
        self.assertIs(harness.connection_calls[0][2], harness.resolver)
        approved_id, approved_request, approved_plan = harness.approval_calls[0]
        self.assertEqual(approved_id, REQUEST_ID)
        self.assertIs(approved_request, spec)
        self.assertEqual(approved_plan, build_plan())

    def test_approved_context_is_single_use_and_retains_no_script_bytes(self):
        harness = PlannerHarness()
        planner = harness.planner()
        spec = RequestSpec(
            machine_alias="app-server",
            mode=ExecutionMode.SCRIPT,
            cwd="/tmp",
            script=b"secret-like test payload that must not be retained",
        )
        planner(REQUEST_ID, spec)
        context = planner.take(REQUEST_ID, spec)

        self.assertIsInstance(context, ApprovedRequestContext)
        self.assertEqual(context.request_sha256, spec.client_request_sha256())
        self.assertFalse(hasattr(context, "request"))
        self.assertFalse(hasattr(context, "script"))
        self.assertEqual(planner.pending_request_ids, ())
        with self.assertRaises(PlanningError):
            planner.take(REQUEST_ID, spec)

    def test_denial_creates_no_consumable_context(self):
        harness = PlannerHarness(ApprovalDecision.DENIED)
        planner = harness.planner()
        spec = request()
        self.assertEqual(planner(REQUEST_ID, spec), ApprovalDecision.DENIED)
        self.assertEqual(planner.pending_request_ids, ())
        with self.assertRaises(PlanningError):
            planner.take(REQUEST_ID, spec)

    def test_changed_request_cannot_consume_approved_plan(self):
        harness = PlannerHarness()
        planner = harness.planner()
        original = request(("printf", "original"))
        changed = request(("printf", "changed"))
        planner(REQUEST_ID, original)
        with self.assertRaisesRegex(PlanningError, "different request bytes"):
            planner.take(REQUEST_ID, changed)
        self.assertEqual(planner.pending_request_ids, (REQUEST_ID,))
        self.assertEqual(planner.take(REQUEST_ID, original).request_id, REQUEST_ID)

    def test_multiple_approved_contexts_remain_request_bound(self):
        harness = PlannerHarness()
        planner = harness.planner()
        planner(REQUEST_ID, request())
        second_request = request(("true",))
        self.assertEqual(
            planner(SECOND_ID, second_request), ApprovalDecision.APPROVED
        )
        self.assertEqual(
            planner.pending_request_ids, tuple(sorted((REQUEST_ID, SECOND_ID)))
        )
        self.assertTrue(planner.discard(REQUEST_ID))
        self.assertFalse(planner.discard(REQUEST_ID))
        self.assertEqual(planner.take(SECOND_ID, second_request).request_id, SECOND_ID)

    def test_unknown_machine_fails_before_snapshot_or_approval(self):
        harness = PlannerHarness()
        planner = harness.planner()
        unknown = RequestSpec(
            machine_alias="unknown",
            mode=ExecutionMode.ARGV,
            cwd="/",
            argv=("true",),
        )
        with self.assertRaisesRegex(PlanningError, "unknown configured machine"):
            planner(REQUEST_ID, unknown)
        self.assertEqual(harness.snapshot_calls, [])
        self.assertEqual(harness.approval_calls, [])

    def test_collection_or_plan_failure_leaves_no_context(self):
        harness = PlannerHarness()
        planner = BoundRequestPlanner(
            harness.config,
            snapshot_collector=lambda *args, **kwargs: (_ for _ in ()).throw(
                RuntimeError("synthetic collector failure")
            ),
            route_builder=harness.route,
            connection_builder=harness.connect,
            endpoint_resolver=harness.resolver,
            approver=harness.approve,
        )
        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            planner(REQUEST_ID, request())
        self.assertEqual(planner.pending_request_ids, ())
        self.assertEqual(harness.approval_calls, [])

    def test_context_rejects_invalid_digest(self):
        with self.assertRaisesRegex(ValueError, "digest"):
            ApprovedRequestContext(REQUEST_ID, "not-a-digest", build_plan())

    def test_simultaneous_planning_is_rejected_before_second_snapshot(self):
        harness = PlannerHarness()
        entered = threading.Event()
        release = threading.Event()

        def blocked_collect(destinations, *, home_gateway):
            harness.snapshot_calls.append((tuple(destinations), home_gateway))
            entered.set()
            if not release.wait(timeout=2):
                raise RuntimeError("test collector release timed out")
            return empty_snapshot()

        planner = BoundRequestPlanner(
            harness.config,
            snapshot_collector=blocked_collect,
            route_builder=harness.route,
            connection_builder=harness.connect,
            endpoint_resolver=harness.resolver,
            approver=harness.approve,
        )
        outcome = []
        worker = threading.Thread(
            target=lambda: outcome.append(planner(REQUEST_ID, request())),
        )
        worker.start()
        self.assertTrue(entered.wait(timeout=1))
        with self.assertRaisesRegex(PlanningError, "currently being planned"):
            planner(SECOND_ID, request(("true",)))
        self.assertEqual(len(harness.snapshot_calls), 1)
        release.set()
        worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome, [ApprovalDecision.APPROVED])


if __name__ == "__main__":
    unittest.main()
