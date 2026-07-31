from pathlib import Path
import tempfile
import unittest

from tmuxgate.executor import RealExecutor
from tmuxgate.result import TransportStatus
from tmuxgate.scheduler import RequestState
from tmuxgate.spool import ResultSpool
from tmuxgate.state import DurableStateStore
from tmuxgate.transport import MasterTransportPool
from test_planning import PlannerHarness, request
from test_remote_job import FakeRemoteBackend
from test_transport import FakeMasterBackend


REQUEST_ID = "0123456789abcdef0123456789abcdef"


class AutoCompletingBackend(FakeRemoteBackend):
    def attach(self, identity):
        viewer = super().attach(identity)
        self.viewer = viewer
        return viewer

    def release_gate(self, identity):
        super().release_gate(identity)
        self.complete(b"stdout-line\n", b"stderr-line\n", 7)
        self.viewer.detach()


class RealExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        (root / "control").mkdir(mode=0o700)
        (root / "state").mkdir(mode=0o700)
        self.master_backend = FakeMasterBackend()
        self.harness = PlannerHarness()
        self.planner = self.harness.planner()
        self.pool = MasterTransportPool(
            root / "control",
            backend=self.master_backend,
            identity_revalidator=lambda endpoint: endpoint,
        )
        self.state = DurableStateStore(root / "state")
        self.spool = ResultSpool(root / "state")

    def tearDown(self):
        self.pool.close_idle()
        self.spool.close()
        self.state.close()
        self.master_backend.close()
        self.temporary.cleanup()

    def approve(self, spec):
        self.planner(REQUEST_ID, spec)

    def executor(self, backend):
        return RealExecutor(
            planner=self.planner,
            transports=self.pool,
            state=self.state,
            spool=self.spool,
            backend_factory=lambda transport: backend,
            poll_interval_seconds=0.001,
            detached_wait_seconds=0.001,
        )

    def test_full_fake_transport_and_remote_job_returns_exact_result_and_done(self):
        spec = request(("printf", "hello"))
        self.approve(spec)
        backend = AutoCompletingBackend()
        executor = self.executor(backend)

        result = executor(REQUEST_ID, spec)

        self.assertEqual(result.transport_status, TransportStatus.COMPLETE)
        self.assertEqual(result.stdout, b"stdout-line\n")
        self.assertEqual(result.stderr, b"stderr-line\n")
        self.assertEqual(result.remote_exit_status, 7)
        self.assertEqual(
            backend.events,
            ["stage", "create-gated", "attach", "release-gate", "collect", "cleanup"],
        )
        self.assertEqual(self.state.load(REQUEST_ID).state, RequestState.RESULT_DELIVERING)
        executor.result_delivery_finished(REQUEST_ID, True)
        self.assertEqual(self.state.load(REQUEST_ID).state, RequestState.DONE)
        spooled = self.spool.load(REQUEST_ID)
        self.assertEqual((spooled.stdout, spooled.stderr, spooled.exit_status), (b"stdout-line\n", b"stderr-line\n", 7))
        self.assertIsNone(self.pool.pinned_request_id)

    def test_transport_failure_is_proven_pre_remote_and_creates_no_job_state(self):
        spec = request(("true",))
        self.approve(spec)
        self.master_backend.fail_next_start = True
        result = self.executor(AutoCompletingBackend())(REQUEST_ID, spec)
        self.assertEqual(result.transport_status, TransportStatus.PRE_REMOTE_FAILURE)
        self.assertEqual(self.state.load_all(), ())
        self.assertIsNone(self.pool.pinned_request_id)

    def test_post_arm_failure_is_incomplete_and_retains_transport_lease(self):
        spec = request(("true",))
        self.approve(spec)
        backend = FakeRemoteBackend()

        def fail_stage(identity, submitted):
            raise RuntimeError("synthetic stage failure")

        backend.stage = fail_stage
        executor = self.executor(backend)
        result = executor(REQUEST_ID, spec)
        self.assertEqual(result.transport_status, TransportStatus.INCOMPLETE)
        self.assertEqual(self.pool.pinned_request_id, REQUEST_ID)
        self.assertEqual(
            self.state.load(REQUEST_ID).state,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        # The retained lease is deliberately not released by the test subject.
        executor._recovery_leases[REQUEST_ID].release()


if __name__ == "__main__":
    unittest.main()
