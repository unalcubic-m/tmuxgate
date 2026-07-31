import unittest

from tmuxgate.scheduler import (
    InvalidTransitionError,
    LeaseBusyError,
    LeaseReleaseReason,
    QueueFullError,
    RequestState,
    SequentialScheduler,
    UnknownRequestError,
)


def request_id(number: int) -> str:
    return f"{number:032x}"


class SequentialSchedulerTests(unittest.TestCase):
    def test_three_isolated_leases_can_run_and_release_independently(self):
        scheduler = SequentialScheduler(
            max_pending_requests=4,
            max_active_remote_commands=3,
        )
        identifiers = tuple(request_id(value) for value in (1, 2, 3, 4))
        for index, identifier in enumerate(identifiers):
            scheduler.submit(identifier, f"machine-{index % 2}")
        for identifier in identifiers[:3]:
            self.assertTrue(scheduler.can_begin_approval)
            self.assertEqual(scheduler.begin_next_approval().request_id, identifier)
            scheduler.approve(identifier)
        self.assertEqual(scheduler.active_count, 3)
        self.assertFalse(scheduler.can_begin_approval)
        scheduler.mark_pre_remote_failure(identifiers[0], detail="pre-remote")
        self.assertTrue(scheduler.can_begin_approval)
        self.assertEqual(
            scheduler.begin_next_approval().request_id, identifiers[3]
        )

    def test_fifo_and_lease_is_acquired_only_when_approval_begins(self):
        scheduler = SequentialScheduler(max_pending_requests=3)
        first = request_id(1)
        second = request_id(2)
        scheduler.submit(first)
        scheduler.submit(second)

        self.assertIsNone(scheduler.lease_owner)
        self.assertEqual(scheduler.pending_request_ids, (first, second))

        selected = scheduler.begin_next_approval()
        self.assertEqual(selected.request_id, first)
        self.assertEqual(scheduler.lease_owner, first)
        self.assertEqual(scheduler.pending_request_ids, (second,))
        with self.assertRaises(LeaseBusyError):
            scheduler.begin_next_approval()

        scheduler.deny(first)
        self.assertEqual(scheduler.begin_next_approval().request_id, second)

    def test_pending_queue_is_bounded_and_cancelled_slot_can_be_reused(self):
        scheduler = SequentialScheduler(max_pending_requests=2)
        first, second, third = (request_id(value) for value in (1, 2, 3))
        scheduler.submit(first)
        scheduler.submit(second)
        with self.assertRaises(QueueFullError):
            scheduler.submit(third)

        cancelled = scheduler.client_disconnected(first)
        self.assertEqual(cancelled.state, RequestState.CANCELLED_BEFORE_APPROVAL)
        self.assertEqual(scheduler.pending_request_ids, (second,))
        scheduler.submit(third)
        self.assertEqual(scheduler.pending_request_ids, (second, third))

    def test_queued_disconnect_cancels_without_disturbing_fifo(self):
        scheduler = SequentialScheduler()
        first, second = request_id(1), request_id(2)
        scheduler.submit(first)
        scheduler.submit(second)

        scheduler.client_disconnected(first)
        selected = scheduler.begin_next_approval()
        self.assertEqual(selected.request_id, second)
        self.assertIsNone(scheduler.request(first).decision)

    def test_denial_and_proven_pre_remote_failure_release_lease(self):
        scheduler = SequentialScheduler()
        denied_id, failed_id = request_id(1), request_id(2)
        scheduler.submit(denied_id)
        scheduler.submit(failed_id)

        scheduler.begin_next_approval()
        denied = scheduler.deny(denied_id)
        self.assertIsNone(scheduler.lease_owner)
        self.assertEqual(denied.lease_release_reason, LeaseReleaseReason.DENIED)

        scheduler.begin_next_approval()
        scheduler.approve(failed_id)
        failed = scheduler.mark_pre_remote_failure(
            failed_id, detail="authentication failed before staging"
        )
        self.assertIsNone(scheduler.lease_owner)
        self.assertEqual(failed.state, RequestState.FAILED_PRE_REMOTE)
        self.assertEqual(
            failed.lease_release_reason, LeaseReleaseReason.PRE_REMOTE_FAILURE
        )

    def test_approved_client_disconnect_does_not_release_or_cancel(self):
        scheduler = SequentialScheduler()
        active_id = request_id(1)
        scheduler.submit(active_id)
        scheduler.begin_next_approval()
        scheduler.approve(active_id)

        disconnected = scheduler.client_disconnected(active_id)
        self.assertFalse(disconnected.client_connected)
        self.assertEqual(disconnected.state, RequestState.APPROVED_PRE_REMOTE)
        self.assertEqual(scheduler.lease_owner, active_id)

        scheduler.mark_remote_may_be_running(active_id)
        self.assertEqual(scheduler.lease_owner, active_id)

    def test_verified_completion_requires_every_release_gate(self):
        scheduler = SequentialScheduler()
        active_id = request_id(1)
        scheduler.submit(active_id)
        scheduler.begin_next_approval()
        scheduler.approve(active_id)
        scheduler.mark_remote_may_be_running(active_id)

        scheduler.mark_remote_completion_proven(active_id, exit_status=7)
        scheduler.mark_local_spool_verified(active_id)
        self.assertEqual(scheduler.lease_owner, active_id)
        with self.assertRaises(InvalidTransitionError):
            scheduler.begin_result_delivery(active_id)

        scheduler.mark_viewer_detached(active_id)
        self.assertEqual(scheduler.lease_owner, active_id)
        released = scheduler.mark_terminal_restored(active_id)
        self.assertIsNone(scheduler.lease_owner)
        self.assertEqual(released.state, RequestState.LEASE_RELEASED)
        self.assertEqual(released.remote_exit_status, 7)
        self.assertEqual(
            released.lease_release_reason,
            LeaseReleaseReason.VERIFIED_COMPLETION,
        )

    def test_terminal_cannot_be_restored_before_viewer_detaches(self):
        scheduler = SequentialScheduler()
        active_id = request_id(1)
        scheduler.submit(active_id)
        scheduler.begin_next_approval()
        scheduler.approve(active_id)
        scheduler.mark_remote_may_be_running(active_id)

        with self.assertRaisesRegex(InvalidTransitionError, "viewer detachment"):
            scheduler.mark_terminal_restored(active_id)
        self.assertEqual(scheduler.lease_owner, active_id)

    def test_possibly_running_recovery_retains_lease_until_proven_safe(self):
        scheduler = SequentialScheduler()
        active_id = request_id(1)
        scheduler.submit(active_id)
        scheduler.begin_next_approval()
        scheduler.approve(active_id)
        scheduler.mark_remote_may_be_running(active_id)

        recovering = scheduler.mark_recovery_required(
            active_id, detail="broker lost the SSH channel"
        )
        self.assertEqual(
            recovering.state,
            RequestState.RECOVERY_REQUIRED_POSSIBLY_RUNNING,
        )
        self.assertEqual(scheduler.lease_owner, active_id)
        with self.assertRaises(InvalidTransitionError):
            scheduler.mark_pre_remote_failure(active_id, detail="unsafe downgrade")

        scheduler.mark_viewer_detached(active_id)
        scheduler.mark_terminal_restored(active_id)
        self.assertEqual(scheduler.lease_owner, active_id)
        scheduler.mark_remote_completion_proven(active_id, exit_status=0)
        released = scheduler.mark_local_spool_verified(active_id)
        self.assertEqual(released.state, RequestState.LEASE_RELEASED)
        self.assertIsNone(scheduler.lease_owner)

    def test_slow_result_delivery_does_not_hold_command_lease(self):
        scheduler = SequentialScheduler()
        first, second = request_id(1), request_id(2)
        scheduler.submit(first)
        scheduler.submit(second)
        scheduler.begin_next_approval()
        scheduler.approve(first)
        scheduler.mark_remote_may_be_running(first)
        scheduler.mark_remote_completion_proven(first, exit_status=0)
        scheduler.mark_local_spool_verified(first)
        scheduler.mark_viewer_detached(first)
        scheduler.mark_terminal_restored(first)

        delivering = scheduler.begin_result_delivery(first)
        self.assertEqual(delivering.state, RequestState.RESULT_DELIVERING)
        self.assertIsNone(scheduler.lease_owner)

        selected = scheduler.begin_next_approval()
        self.assertEqual(selected.request_id, second)
        self.assertEqual(scheduler.lease_owner, second)
        done = scheduler.finish_result_delivery(first)
        self.assertEqual(done.state, RequestState.DONE)
        self.assertEqual(scheduler.lease_owner, second)

    def test_terminal_records_can_be_forgotten_but_active_work_cannot(self):
        scheduler = SequentialScheduler()
        cancelled, completed = request_id(1), request_id(2)
        scheduler.submit(cancelled)
        scheduler.submit(completed)

        scheduler.client_disconnected(cancelled)
        scheduler.forget_terminal(cancelled)
        with self.assertRaises(UnknownRequestError):
            scheduler.request(cancelled)

        scheduler.begin_next_approval()
        with self.assertRaises(InvalidTransitionError):
            scheduler.forget_terminal(completed)
        scheduler.deny(completed)
        scheduler.begin_result_delivery(completed)
        scheduler.finish_result_delivery(completed)
        forgotten = scheduler.forget_terminal(completed)
        self.assertEqual(forgotten.state, RequestState.DONE)
        self.assertEqual(scheduler.record_count, 0)


if __name__ == "__main__":
    unittest.main()
