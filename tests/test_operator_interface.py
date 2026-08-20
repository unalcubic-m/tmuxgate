from contextlib import nullcontext
from dataclasses import FrozenInstanceError, replace
import io
import threading
import unittest

from tmuxgate.approval import ApprovalDecision, ApprovalTerminal
from tmuxgate.models import ExecutionMode, RequestSpec
from tmuxgate.operator_interface import (
    ActivityKind,
    ConnectionPhase,
    ExecutionApprovalPrompt,
    MachineDisablePrompt,
    OperationalActivity,
    OperatorDecision,
    OperatorInterfaceError,
    PendingDecision,
    PlainTerminalInterface,
    PromptQueue,
    RemoteMutationState,
    RemoteCommandState,
    RouteFallbackPrompt,
    SecretInputAuthorizationPrompt,
    SecretInputRecipient,
    SshRetryPrompt,
    require_operator_decision,
    resolve_operator_prompt,
)
from test_connection_plan import REQUEST_ID, build_plan


SECOND_REQUEST_ID = "fedcba9876543210fedcba9876543210"


class FakeTerminalArbiter:
    def claim(self, **_keywords):
        return nullcontext()

    def poll_dashboard_line(self, **_keywords):
        return None


class HumanPromptMethodsForbiddenAutomationInterface(PlainTerminalInterface):
    def _human_method_called(self, _prompt):
        raise AssertionError("Automation called a request-specific human prompt method")

    request_execution_approval = _human_method_called
    request_ssh_retry = _human_method_called
    request_fallback = _human_method_called
    request_machine_disable = _human_method_called
    request_secret_input_authorization = _human_method_called


def request(*, script: bytes | None = None) -> RequestSpec:
    if script is not None:
        return RequestSpec(
            "app-server",
            ExecutionMode.SCRIPT,
            "/opt/docker",
            script=script,
        )
    return RequestSpec(
        "app-server",
        ExecutionMode.ARGV,
        "/opt/docker",
        argv=("printf", "%s", "hello"),
    )


class StructuredPromptTests(unittest.TestCase):
    def setUp(self):
        self.request = request()
        self.plan = build_plan()

    def test_execution_prompt_is_immutable_and_rejects_mismatched_identity(self):
        with self.assertRaises(TypeError):
            ExecutionApprovalPrompt()
        with self.assertRaisesRegex(ValueError, "prompt_id"):
            ExecutionApprovalPrompt.create(
                REQUEST_ID,
                self.request,
                self.plan,
                prompt_id="malformed",
            )
        with self.assertRaisesRegex(ValueError, "connection_plan is required"):
            ExecutionApprovalPrompt.create(REQUEST_ID, self.request, None)
        fake_prompt = ExecutionApprovalPrompt.create(
            REQUEST_ID,
            self.request,
            None,
            unbound_fake=True,
        )
        self.assertTrue(fake_prompt.unbound_fake)
        with self.assertRaisesRegex(ValueError, "must not include"):
            ExecutionApprovalPrompt.create(
                REQUEST_ID,
                self.request,
                self.plan,
                unbound_fake=True,
            )
        prompt = ExecutionApprovalPrompt.create(REQUEST_ID, self.request, self.plan)
        self.assertEqual(prompt.client_request_sha256, self.request.client_request_sha256())
        self.assertEqual(prompt.connection_plan_sha256, self.plan.plan_sha256)
        with self.assertRaises(FrozenInstanceError):
            prompt.request_id = SECOND_REQUEST_ID
        with self.assertRaisesRegex(ValueError, "client request digest"):
            replace(prompt, client_request_sha256="0" * 64)
        different_request = RequestSpec(
            "other", ExecutionMode.ARGV, "/", argv=("true",)
        )
        with self.assertRaisesRegex(ValueError, "different request machine"):
            ExecutionApprovalPrompt.create(REQUEST_ID, different_request, self.plan)
        with self.assertRaisesRegex(ValueError, "canonical data"):
            ExecutionApprovalPrompt.create(
                REQUEST_ID,
                self.request,
                replace(self.plan, plan_sha256="0" * 64),
            )

    def test_retry_rejects_missing_endpoint_mutation_and_binding_mismatch(self):
        diagnostics = b"ssh: denied\x1b]8;;https://evil.invalid\x07\n"
        prompt = SshRetryPrompt.create(
            REQUEST_ID,
            self.request,
            self.plan,
            endpoint_id="home-lan",
            failure_detail="OpenSSH exited with status 255",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
            openssh_diagnostics=diagnostics,
        )
        self.assertEqual(prompt.openssh_diagnostics, diagnostics)
        self.assertEqual(prompt.retry_number, 1)
        self.assertEqual(prompt.retry_limit, 1)
        self.assertIs(prompt.remote_command_state, RemoteCommandState.NOT_STARTED)
        with self.assertRaisesRegex(ValueError, "not present"):
            SshRetryPrompt.create(
                REQUEST_ID,
                self.request,
                self.plan,
                endpoint_id="unknown",
                failure_detail="failed",
                remote_mutation_state=RemoteMutationState.NOT_STARTED,
            )
        with self.assertRaisesRegex(ValueError, "forbidden"):
            SshRetryPrompt.create(
                REQUEST_ID,
                self.request,
                self.plan,
                endpoint_id="home-lan",
                failure_detail="uncertain enrollment",
                remote_mutation_state=RemoteMutationState.MAY_HAVE_STARTED,
            )
        with self.assertRaisesRegex(ValueError, "retry binding"):
            replace(prompt, retry_binding_sha256="f" * 64)
        with self.assertRaisesRegex(ValueError, "diagnostic digest"):
            replace(prompt, openssh_diagnostics=b"changed")
        with self.assertRaisesRegex(ValueError, "one-retry policy"):
            SshRetryPrompt.create(
                REQUEST_ID,
                self.request,
                self.plan,
                endpoint_id="home-lan",
                failure_detail="failed",
                remote_mutation_state=RemoteMutationState.NOT_STARTED,
                retry_limit=2,
            )

    def test_fallback_requires_adjacent_exact_routes_and_truthful_mutation(self):
        prompt = RouteFallbackPrompt.create(
            REQUEST_ID,
            self.request,
            self.plan,
            failed_endpoint_id="home-lan",
            fallback_endpoint_id="wireguard",
            failure_detail="route failed",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
            openssh_diagnostics=b"exact fallback diagnostic\n",
        )
        self.assertEqual(prompt.connection_plan_sha256, self.plan.plan_sha256)
        self.assertEqual(prompt.openssh_diagnostics, b"exact fallback diagnostic\n")
        with self.assertRaisesRegex(ValueError, "next approved route"):
            RouteFallbackPrompt.create(
                REQUEST_ID,
                self.request,
                self.plan,
                failed_endpoint_id="wireguard",
                fallback_endpoint_id="home-lan",
                failure_detail="wrong order",
                remote_mutation_state=RemoteMutationState.NOT_STARTED,
            )
        with self.assertRaisesRegex(ValueError, "forbidden"):
            RouteFallbackPrompt.create(
                REQUEST_ID,
                self.request,
                self.plan,
                failed_endpoint_id="home-lan",
                fallback_endpoint_id="wireguard",
                failure_detail="possible write",
                remote_mutation_state=RemoteMutationState.STARTED,
            )

    def test_secret_authorization_binds_request_command_endpoint_and_viewer(self):
        prompt = SecretInputAuthorizationPrompt.create(
            REQUEST_ID,
            self.request,
            self.plan,
            endpoint_id="home-lan",
            viewer_session_id="tmuxgate-0123456789ab",
        )
        changed = request(script=b"printf changed\n")
        with self.assertRaisesRegex(ValueError, "client request digest"):
            replace(prompt, request=changed)
        with self.assertRaisesRegex(ValueError, "viewer_session_id"):
            SecretInputAuthorizationPrompt.create(
                REQUEST_ID,
                self.request,
                self.plan,
                endpoint_id="home-lan",
                viewer_session_id="",
            )
        with self.assertRaisesRegex(ValueError, "viewer_session_id"):
            SecretInputAuthorizationPrompt.create(
                REQUEST_ID,
                self.request,
                self.plan,
                endpoint_id="home-lan",
                viewer_session_id="tmuxgate-0123456789aZ",
            )
        recipient = SecretInputRecipient(
            REQUEST_ID, self.request, self.plan, "home-lan"
        )
        replacement = recipient.create_prompt("tmuxgate-0123456789ab")
        self.assertNotEqual(replacement.prompt_id, prompt.prompt_id)
        self.assertEqual(replacement.request_id, REQUEST_ID)

    def test_activity_requires_valid_structured_identity(self):
        event = OperationalActivity.create(
            ActivityKind.STATUS,
            "connecting",
            request_id=REQUEST_ID,
            machine_name="app-server",
            endpoint_id="home-lan",
            details=(("plan_sha256", self.plan.plan_sha256),),
        )
        self.assertEqual(event.request_id, REQUEST_ID)
        with self.assertRaisesRegex(ValueError, "request ID"):
            OperationalActivity.create(
                ActivityKind.STATUS, "bad", request_id="not-a-request"
            )
        progress = OperationalActivity.create(
            ActivityKind.CONNECTION,
            "remote execution is running",
            request_id=REQUEST_ID,
            machine_name="app-server",
            endpoint_id="home-lan",
            connection_phase=ConnectionPhase.RUNNING,
            remote_mutation_state=RemoteMutationState.STARTED,
        )
        self.assertIs(progress.connection_phase, ConnectionPhase.RUNNING)
        self.assertIs(
            progress.remote_mutation_state, RemoteMutationState.STARTED
        )
        with self.assertRaisesRegex(ValueError, "requires a connection phase"):
            OperationalActivity.create(
                ActivityKind.CONNECTION,
                "missing phase",
                request_id=REQUEST_ID,
                machine_name="app-server",
            )
        with self.assertRaisesRegex(ValueError, "requires remote mutation state"):
            OperationalActivity.create(
                ActivityKind.CONNECTION,
                "missing mutation truth",
                request_id=REQUEST_ID,
                machine_name="app-server",
                connection_phase=ConnectionPhase.CONNECTING,
            )


class DecisionPrimitiveTests(unittest.TestCase):
    def prompt(self, request_id=REQUEST_ID):
        return ExecutionApprovalPrompt.create(request_id, request(), build_plan())

    def test_decision_resolves_exact_prompt_once(self):
        prompt = self.prompt()
        pending = PendingDecision(prompt)
        approved = OperatorDecision.for_prompt(prompt, ApprovalDecision.APPROVED)
        self.assertTrue(pending.resolve(approved))
        self.assertFalse(pending.resolve(approved))
        self.assertFalse(pending.deny())
        self.assertIs(pending.wait().decision, ApprovalDecision.APPROVED)

    def test_stale_or_other_request_decision_cannot_resolve_replacement(self):
        old_prompt = self.prompt()
        new_prompt = self.prompt()
        other_request = self.prompt(SECOND_REQUEST_ID)
        replacement = PendingDecision(new_prompt)
        stale = OperatorDecision.for_prompt(old_prompt, ApprovalDecision.APPROVED)
        wrong_request = OperatorDecision.for_prompt(
            other_request, ApprovalDecision.APPROVED
        )
        self.assertFalse(replacement.resolve(stale))
        self.assertFalse(replacement.resolve(wrong_request))
        self.assertTrue(replacement.deny())

    def test_worker_validation_rejects_interface_decision_for_other_prompt(self):
        expected = self.prompt()
        other = self.prompt()
        with self.assertRaisesRegex(RuntimeError, "different prompt"):
            require_operator_decision(
                expected,
                OperatorDecision.for_prompt(other, ApprovalDecision.APPROVED),
            )

    def test_worker_validation_rejects_stale_retry_decision(self):
        plan = build_plan()
        expected = SshRetryPrompt.create(
            REQUEST_ID,
            request(),
            plan,
            endpoint_id="home-lan",
            failure_detail="first failure",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
        )
        stale = SshRetryPrompt.create(
            REQUEST_ID,
            request(),
            plan,
            endpoint_id="home-lan",
            failure_detail="earlier failure",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
        )
        with self.assertRaisesRegex(RuntimeError, "different prompt"):
            require_operator_decision(
                expected,
                OperatorDecision.for_prompt(stale, ApprovalDecision.APPROVED),
            )

    def test_queue_is_fifo_and_close_denies_every_unresolved_prompt(self):
        prompts = [self.prompt(), self.prompt(), self.prompt()]
        prompt_queue = PromptQueue()
        pending = [prompt_queue.submit(prompt) for prompt in prompts]
        queued = [prompt_queue.next_prompt(timeout=0.1) for _ in prompts]
        self.assertEqual([item.sequence for item in queued], [0, 1, 2])
        self.assertEqual([item.prompt for item in queued], prompts)
        prompt_queue.close()
        self.assertTrue(
            all(item.wait().decision is ApprovalDecision.DENIED for item in pending)
        )
        closed_prompt = self.prompt()
        self.assertIs(
            prompt_queue.submit(closed_prompt).wait().decision,
            ApprovalDecision.DENIED,
        )

    def test_prompt_identity_cannot_be_reused_after_resolution(self):
        prompt_queue = PromptQueue()
        prompt = self.prompt()
        pending = prompt_queue.submit(prompt)
        pending.deny()
        with self.assertRaisesRegex(RuntimeError, "already submitted"):
            prompt_queue.submit(prompt)
        prompt_queue.close()

    def test_cancellation_and_abandonment_fail_closed(self):
        cancelled = PendingDecision(self.prompt())
        abandoned = PendingDecision(self.prompt())
        self.assertTrue(cancelled.cancel())
        self.assertTrue(abandoned.abandon())
        self.assertIs(cancelled.wait().decision, ApprovalDecision.DENIED)
        self.assertIs(abandoned.wait().decision, ApprovalDecision.DENIED)


class PlainTerminalInterfaceTests(unittest.TestCase):
    def test_plain_external_session_keeps_existing_arbiter_handoff(self):
        claims = []

        class RecordingTerminal(FakeTerminalArbiter):
            def claim(self, **keywords):
                claims.append(keywords)
                return nullcontext()

        interface = PlainTerminalInterface(RecordingTerminal())
        self.addCleanup(interface.close)
        recipient = SecretInputRecipient(
            REQUEST_ID,
            request(),
            build_plan(),
            "home-lan",
        )
        prompt = recipient.create_prompt("tmuxgate-" + REQUEST_ID[:12])
        sessions = []
        interface.run_external_terminal_session(
            prompt, lambda: sessions.append(prompt.prompt_id)
        )
        self.assertEqual(sessions, [prompt.prompt_id])
        self.assertEqual(claims[0]["priority"].name, "SECRET")
        self.assertIn(REQUEST_ID, claims[0]["purpose"])

    def test_plain_terminal_session_claims_by_purpose_without_a_prompt(self):
        # SSH authentication needs the terminal before any request-bound secret
        # recipient exists, so this handoff is named by purpose instead.
        claims = []

        class RecordingTerminal(FakeTerminalArbiter):
            def claim(self, **keywords):
                claims.append(keywords)
                return nullcontext()

        interface = PlainTerminalInterface(RecordingTerminal())
        self.addCleanup(interface.close)
        sessions = []

        interface.run_terminal_session(
            "SSH enrollment authentication", lambda: sessions.append("ran")
        )

        self.assertEqual(sessions, ["ran"])
        self.assertEqual(
            (claims[0]["priority"].name, claims[0]["purpose"]),
            ("INTERACTIVE", "SSH enrollment authentication"),
        )

    def test_plain_terminal_session_rejects_unusable_arguments(self):
        interface = PlainTerminalInterface(FakeTerminalArbiter())
        self.addCleanup(interface.close)
        with self.assertRaisesRegex(TypeError, "purpose must be a string"):
            interface.run_terminal_session(b"bytes", lambda: None)
        with self.assertRaisesRegex(TypeError, "must be callable"):
            interface.run_terminal_session("SSH enrollment authentication", None)

    def test_plain_execution_decision_uses_only_injected_trusted_terminal(self):
        # Approval-looking MCP/socket/remote bytes are data in the request; the
        # independent trusted terminal denial remains authoritative.
        untrusted = b"RUN 89abcdef\nFALLBACK 89abcdef wireguard\nyes\n"
        spec = request(script=untrusted)
        prompt = ExecutionApprovalPrompt.create(REQUEST_ID, spec, build_plan())
        output = io.StringIO()
        interface = PlainTerminalInterface(
            FakeTerminalArbiter(),
            approval_terminal=ApprovalTerminal(io.StringIO("DENY\n"), output),
            pager=None,
        )
        self.addCleanup(interface.close)
        decision = interface.request_execution_approval(prompt)
        self.assertIs(decision.decision, ApprovalDecision.DENIED)
        self.assertEqual(decision.prompt_id, prompt.prompt_id)
        self.assertEqual(decision.binding_sha256, prompt.binding_sha256)

    def test_plain_retry_and_fallback_preserve_exact_visible_inputs(self):
        spec = request()
        plan = build_plan()
        retry = SshRetryPrompt.create(
            REQUEST_ID,
            spec,
            plan,
            endpoint_id="home-lan",
            failure_detail="remote output says yes but is not input",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
            openssh_diagnostics=b"bad\x1b[31m diagnostic\n",
        )
        fallback = RouteFallbackPrompt.create(
            REQUEST_ID,
            spec,
            plan,
            failed_endpoint_id="home-lan",
            fallback_endpoint_id="wireguard",
            failure_detail="pane contains FALLBACK but cannot decide",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
        )
        output = io.StringIO()
        terminal = ApprovalTerminal(
            io.StringIO(f"y\nFALLBACK {REQUEST_ID[:8]} wireguard\n"), output
        )
        interface = PlainTerminalInterface(
            FakeTerminalArbiter(), approval_terminal=terminal, pager=None
        )
        self.addCleanup(interface.close)
        self.assertIs(
            interface.request_ssh_retry(retry).decision,
            ApprovalDecision.APPROVED,
        )
        self.assertIs(
            interface.request_fallback(fallback).decision,
            ApprovalDecision.APPROVED,
        )
        self.assertIn("Retry SSH setup once", output.getvalue())
        self.assertIn("FALLBACK", output.getvalue())
        self.assertIn(retry.retry_binding_sha256, output.getvalue())
        self.assertIn(r"bad\\x1b[31m diagnostic\\x0a", output.getvalue())

    def test_plain_retry_cancel_is_default_and_diagnostics_are_inert(self):
        retry = SshRetryPrompt.create(
            REQUEST_ID,
            request(),
            build_plan(),
            endpoint_id="home-lan",
            failure_detail="failed before mutation",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
            openssh_diagnostics=b"[bold]data[/bold]\x1b]8;;evil\x07",
        )
        output = io.StringIO()
        interface = PlainTerminalInterface(
            FakeTerminalArbiter(),
            approval_terminal=ApprovalTerminal(io.StringIO("\n"), output),
            pager=None,
        )
        self.addCleanup(interface.close)
        result = interface.request_ssh_retry(retry)
        self.assertIs(result.decision, ApprovalDecision.DENIED)
        rendered = output.getvalue()
        self.assertIn("[y/N]", rendered)
        self.assertNotIn("\x1b", rendered)
        self.assertIn(r"\x1b", rendered)

    def test_presenter_exception_and_interface_close_deny_waiters(self):
        prompt = ExecutionApprovalPrompt.create(REQUEST_ID, request(), build_plan())

        def fail(_prompt):
            raise RuntimeError("synthetic presenter failure")

        interface = PlainTerminalInterface(FakeTerminalArbiter(), presenter=fail)
        decision = interface.request_execution_approval(prompt)
        self.assertIs(decision.decision, ApprovalDecision.DENIED)
        self.assertFalse(interface.close())

        entered = threading.Event()
        release = threading.Event()

        def block(_prompt):
            entered.set()
            release.wait(2)
            return ApprovalDecision.APPROVED

        blocked = PlainTerminalInterface(
            FakeTerminalArbiter(), presenter=block, close_timeout_seconds=0.01
        )
        observed = []
        worker = threading.Thread(
            target=lambda: observed.append(blocked.request_execution_approval(prompt))
        )
        worker.start()
        self.assertTrue(entered.wait(1))
        self.assertFalse(blocked.close())
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertIs(observed[0].decision, ApprovalDecision.DENIED)
        release.set()
        blocked._thread.join(timeout=1)
        self.assertFalse(blocked._thread.is_alive())

    def test_secret_authorization_requires_exact_trusted_terminal_phrase(self):
        spec = request()
        plan = build_plan()
        prompt = SecretInputAuthorizationPrompt.create(
            REQUEST_ID,
            spec,
            plan,
            endpoint_id="home-lan",
            viewer_session_id="tmuxgate-0123456789ab",
        )
        output = io.StringIO()
        interface = PlainTerminalInterface(
            FakeTerminalArbiter(),
            approval_terminal=ApprovalTerminal(
                io.StringIO(f"forward {SECOND_REQUEST_ID}\n\n"), output
            ),
            approval_mode="always",
        )
        self.addCleanup(interface.close)
        self.assertIs(
            interface.request_secret_input_authorization(prompt).decision,
            ApprovalDecision.DENIED,
        )
        rendered = output.getvalue()
        self.assertIn(f"request_id: {REQUEST_ID}", rendered)
        self.assertIn('machine: "app-server"', rendered)
        self.assertIn("approved_argv:", rendered)
        self.assertIn("every byte typed", rendered)

        approved_prompt = SecretInputAuthorizationPrompt.create(
            REQUEST_ID,
            spec,
            plan,
            endpoint_id="home-lan",
            viewer_session_id="tmuxgate-0123456789ab",
        )
        approved = PlainTerminalInterface(
            FakeTerminalArbiter(),
            approval_terminal=ApprovalTerminal(
                io.StringIO(f"forward {REQUEST_ID}\n"), io.StringIO()
            ),
            approval_mode="always",
        )
        self.addCleanup(approved.close)
        self.assertIs(
            approved.request_secret_input_authorization(approved_prompt).decision,
            ApprovalDecision.APPROVED,
        )

    def test_automatic_policy_decisions_are_one_shot_and_close_denies(self):
        interface = PlainTerminalInterface(
            FakeTerminalArbiter(),
            approval_mode="disabled",
        )
        prompt = ExecutionApprovalPrompt.create(REQUEST_ID, request(), build_plan())
        self.assertIs(
            interface.request_execution_approval(prompt).decision,
            ApprovalDecision.APPROVED,
        )
        with self.assertRaisesRegex(OperatorInterfaceError, "already submitted"):
            interface.request_execution_approval(prompt)
        secret = SecretInputAuthorizationPrompt.create(
            SECOND_REQUEST_ID,
            request(),
            build_plan(),
            endpoint_id="home-lan",
            viewer_session_id="tmuxgate-0123456789ab",
        )
        self.assertIs(
            interface.request_secret_input_authorization(secret).decision,
            ApprovalDecision.DENIED,
        )
        self.assertTrue(interface.close())
        after_close = ExecutionApprovalPrompt.create(
            SECOND_REQUEST_ID,
            request(),
            build_plan(),
        )
        self.assertIs(
            interface.request_execution_approval(after_close).decision,
            ApprovalDecision.DENIED,
        )

    def test_automation_resolves_every_prompt_kind_without_queue_or_terminal(self):
        interface = HumanPromptMethodsForbiddenAutomationInterface(
            FakeTerminalArbiter(),
            approval_mode="disabled",
        )
        self.addCleanup(interface.close)
        exact_request = request()
        plan = build_plan()
        execution = ExecutionApprovalPrompt.create(
            REQUEST_ID,
            exact_request,
            plan,
        )
        retry = SshRetryPrompt.create(
            SECOND_REQUEST_ID,
            exact_request,
            plan,
            endpoint_id="home-lan",
            failure_detail="initial authentication failed",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
        )
        fallback = RouteFallbackPrompt.create(
            "3" * 32,
            exact_request,
            plan,
            failed_endpoint_id="home-lan",
            fallback_endpoint_id="wireguard",
            failure_detail="home route failed",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
        )
        disable = MachineDisablePrompt.create(
            "4" * 32,
            exact_request,
            plan,
            failure_detail="all routes failed",
            remote_mutation_state=RemoteMutationState.NOT_STARTED,
        )
        secret = SecretInputAuthorizationPrompt.create(
            "5" * 32,
            exact_request,
            plan,
            endpoint_id="home-lan",
            viewer_session_id="tmuxgate-555555555555",
        )

        decisions = (
            resolve_operator_prompt(interface, execution).decision,
            resolve_operator_prompt(interface, retry).decision,
            resolve_operator_prompt(interface, fallback).decision,
            resolve_operator_prompt(interface, disable).decision,
            resolve_operator_prompt(interface, secret).decision,
        )

        self.assertEqual(
            decisions,
            (
                ApprovalDecision.APPROVED,
                ApprovalDecision.APPROVED,
                ApprovalDecision.APPROVED,
                ApprovalDecision.DENIED,
                ApprovalDecision.DENIED,
            ),
        )
        self.assertIsNone(interface._prompts.next_prompt(timeout=0))
        audit = tuple(
            event
            for event in interface.activity_history
            if event.kind is ActivityKind.BROKER_AUDIT
        )
        self.assertEqual(len(audit), 5)
        self.assertEqual(
            tuple(dict(event.details)["binding_sha256"] for event in audit),
            tuple(
                prompt.binding_sha256
                for prompt in (execution, retry, fallback, disable, secret)
            ),
        )

        called = []
        with self.assertRaisesRegex(OperatorInterfaceError, "human prompt"):
            interface._request(execution)
        with self.assertRaisesRegex(OperatorInterfaceError, "forbids"):
            interface.run_terminal_session("forbidden", lambda: called.append(True))
        with self.assertRaisesRegex(OperatorInterfaceError, "forbids"):
            interface.run_external_terminal_session(
                secret,
                lambda: called.append(True),
            )
        self.assertEqual(called, [])

    def test_activity_history_is_bounded(self):
        interface = PlainTerminalInterface(
            FakeTerminalArbiter(), activity_capacity=2
        )
        self.addCleanup(interface.close)
        for message in ("one", "two", "three"):
            interface.publish_activity(
                OperationalActivity.create(ActivityKind.BROKER_AUDIT, message)
            )
        self.assertEqual(
            [event.message for event in interface.activity_history],
            ["two", "three"],
        )


if __name__ == "__main__":
    unittest.main()
