"""Bounded application service coordinating reasoner, gateway, policy, and audit."""

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

from pydantic import TypeAdapter, ValidationError

from security_triage_agent.application.orchestration_contracts import (
    AccumulatedEvidence,
    OrchestrationLimits,
    OrchestrationOutcome,
    OrchestrationReasonCode,
    ReasonerCandidate,
    ReasonerContext,
    ReasonerStep,
    ReasonerToolCall,
)
from security_triage_agent.application.persistence import (
    AuditEvent,
    AuditOutcome,
    TriageExecutionRecord,
)
from security_triage_agent.application.policy import (
    AuthorizedActionScope,
    CandidateAssessment,
    DeterministicPolicy,
    PolicyDecision,
)
from security_triage_agent.application.ports.reasoner import (
    AgentReasoner,
    Clock,
    IdentifierGenerator,
)
from security_triage_agent.application.ports.repositories import UnitOfWork
from security_triage_agent.application.tool_gateway import (
    EntityScope,
    GatewayLimits,
    GatewayStatus,
    ProposedToolRequest,
    ToolExecutionContext,
    ToolGateway,
    ToolInvocationRecord,
)
from security_triage_agent.domain.alerts import SecurityAlert
from security_triage_agent.domain.evidence import EvidenceReference, ToolCallReference
from security_triage_agent.domain.states import TriageExecutionState
from security_triage_agent.domain.triage import Disposition

UnitOfWorkFactory = Callable[[], UnitOfWork]


class TriageOrchestrator:
    """Enforce deterministic flow around an advisory reasoner."""

    def __init__(
        self,
        *,
        reasoner: AgentReasoner,
        gateway: ToolGateway,
        policy: DeterministicPolicy,
        uow_factory: UnitOfWorkFactory,
        clock: Clock,
        identifiers: IdentifierGenerator,
        orchestration_limits: OrchestrationLimits,
        gateway_limits: GatewayLimits,
    ) -> None:
        self._reasoner = reasoner
        self._gateway = gateway
        self._policy = policy
        self._uow_factory = uow_factory
        self._clock = clock
        self._ids = identifiers
        self._limits = orchestration_limits
        self._gateway_limits = gateway_limits
        self._step_adapter: TypeAdapter[ReasonerStep] = TypeAdapter(ReasonerStep)

    def run(
        self,
        alert: SecurityAlert,
        *,
        idempotency_key: str,
        execution_id: str,
        correlation_id: str,
    ) -> OrchestrationOutcome:
        replay = self._find_replay(idempotency_key, execution_id, correlation_id)
        if replay is not None:
            return replay
        if not self._persist_start(alert, idempotency_key, execution_id, correlation_id):
            return self._persistence_failure(execution_id, correlation_id)

        gateway_context = ToolExecutionContext(
            execution_id=execution_id,
            correlation_id=correlation_id,
            entity_scope=EntityScope.from_alert(alert),
            limits=self._gateway_limits,
        )
        action_scope = AuthorizedActionScope.from_entities(alert.entities)
        accumulated: list[AccumulatedEvidence] = []
        started_ms = self._clock.monotonic_ms()
        termination: OrchestrationReasonCode | None = None
        candidate: CandidateAssessment | None = None

        for iteration in range(1, self._limits.max_iterations + 1):
            elapsed_ms = self._clock.monotonic_ms() - started_ms
            if elapsed_ms >= self._limits.deadline_ms:
                termination = OrchestrationReasonCode.DEADLINE_EXCEEDED
                break
            context = ReasonerContext(
                alert=alert,
                evidence=tuple(accumulated),
                iteration=iteration,
                remaining_iterations=self._limits.max_iterations - iteration,
                remaining_total_tool_calls=max(
                    0, self._gateway_limits.total_calls - gateway_context.total_calls_used
                ),
            )
            if len(context.model_dump_json().encode()) > self._limits.max_context_bytes:
                termination = OrchestrationReasonCode.CONTEXT_LIMIT
                break
            executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="reasoner")
            future = executor.submit(self._reasoner.next_step, context)
            try:
                raw_step = future.result(timeout=(self._limits.deadline_ms - elapsed_ms) / 1000)
            except FutureTimeoutError:
                future.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
                termination = OrchestrationReasonCode.DEADLINE_EXCEEDED
                break
            except Exception:
                executor.shutdown(wait=False, cancel_futures=True)
                termination = OrchestrationReasonCode.REASONER_FAILURE
                break
            executor.shutdown(wait=True)
            try:
                step = self._step_adapter.validate_python(raw_step)
            except (ValidationError, TypeError, ValueError):
                termination = OrchestrationReasonCode.INVALID_REASONER_OUTPUT
                break
            if isinstance(step, ReasonerCandidate):
                candidate = step.candidate
                if not self._candidate_references_are_valid(candidate, accumulated):
                    termination = OrchestrationReasonCode.EVIDENCE_REFERENCE_VIOLATION
                    candidate = None
                break
            if isinstance(step, ReasonerToolCall):
                result = self._gateway.invoke(
                    ProposedToolRequest(
                        call_id=step.call_id,
                        tool_name=step.tool_name,
                        arguments=step.arguments,
                    ),
                    gateway_context,
                )
                invocation = gateway_context.invocation_records[-1]
                if not self._persist_tool(invocation, result.result):
                    return self._persistence_failure(execution_id, correlation_id)
                if result.status is not GatewayStatus.SUCCESS:
                    termination = (
                        OrchestrationReasonCode.TOOL_REQUEST_DENIED
                        if result.authorization.value == "DENIED"
                        else OrchestrationReasonCode.TOOL_FAILURE
                    )
                    break
                if len(accumulated) >= self._limits.max_evidence_items:
                    termination = OrchestrationReasonCode.CONTEXT_LIMIT
                    break
                accumulated.append(self._to_evidence(invocation, result.result or {}))
        else:
            termination = OrchestrationReasonCode.ITERATION_LIMIT

        if candidate is None:
            decision = self._safe_policy_decision(alert, action_scope)
            reason = termination or OrchestrationReasonCode.INVALID_REASONER_OUTPUT
        else:
            decision = self._policy.evaluate(
                candidate,
                alert_id=alert.alert_id,
                action_scope=action_scope,
                timestamp=self._clock.now(),
            )
            reason = (
                OrchestrationReasonCode.POLICY_SAFE_REVIEW
                if decision.result.disposition is Disposition.NEEDS_REVIEW
                else OrchestrationReasonCode.COMPLETED
            )
        if not self._persist_final(execution_id, correlation_id, decision, reason):
            return self._persistence_failure(execution_id, correlation_id)
        return OrchestrationOutcome(
            execution_id=execution_id,
            correlation_id=correlation_id,
            durable=True,
            reason_code=reason,
            result=decision.result,
            policy_decision=decision,
        )

    def _find_replay(
        self, key: str, execution_id: str, correlation_id: str
    ) -> OrchestrationOutcome | None:
        try:
            with self._uow_factory() as uow:
                existing = uow.executions.get_by_idempotency_key(key)
                if existing is None:
                    return None
                result = uow.triage_results.get_for_execution(existing.execution_id)
                return OrchestrationOutcome(
                    execution_id=existing.execution_id,
                    correlation_id=correlation_id,
                    durable=True,
                    reason_code=OrchestrationReasonCode.IDEMPOTENT_REPLAY,
                    result=result,
                )
        except Exception:
            return self._persistence_failure(execution_id, correlation_id)

    def _persist_start(
        self, alert: SecurityAlert, key: str, execution_id: str, correlation_id: str
    ) -> bool:
        now = self._clock.now()
        try:
            with self._uow_factory() as uow:
                if uow.alerts.get(alert.alert_id) is None:
                    uow.alerts.add(alert)
                    uow.flush()
                uow.executions.add(
                    TriageExecutionRecord(
                        execution_id=execution_id,
                        alert_id=alert.alert_id,
                        state=TriageExecutionState.RUNNING,
                        idempotency_key=key,
                        created_at=now,
                        updated_at=now,
                    )
                )
                uow.audit.append(
                    self._audit(
                        "triage.execution_started",
                        execution_id,
                        correlation_id,
                        {"state": "RUNNING"},
                    )
                )
                uow.commit()
            return True
        except Exception:
            return False

    def _persist_tool(
        self, invocation: ToolInvocationRecord, result: dict[str, object] | None
    ) -> bool:
        try:
            with self._uow_factory() as uow:
                uow.tool_invocations.add(invocation, result)
                uow.audit.append(
                    self._audit(
                        "triage.tool_invoked",
                        invocation.execution_id,
                        invocation.correlation_id,
                        {
                            "call_id": invocation.call_id,
                            "tool_name": invocation.tool_name,
                            "authorization": invocation.authorization.value,
                            "outcome": invocation.outcome.value,
                        },
                        outcome=(
                            AuditOutcome.SUCCESS
                            if invocation.outcome is GatewayStatus.SUCCESS
                            else AuditOutcome.DENIED
                        ),
                    )
                )
                uow.commit()
            return True
        except Exception:
            return False

    def _persist_final(
        self,
        execution_id: str,
        correlation_id: str,
        decision: PolicyDecision,
        reason: OrchestrationReasonCode,
    ) -> bool:
        terminal = (
            TriageExecutionState.NEEDS_REVIEW
            if decision.result.disposition is Disposition.NEEDS_REVIEW
            else TriageExecutionState.COMPLETED
        )
        try:
            with self._uow_factory() as uow:
                existing = uow.executions.get(execution_id)
                if existing is None:
                    return False
                for action in decision.result.recommended_actions:
                    uow.actions.add(execution_id, action)
                if decision.result.recommended_actions:
                    uow.flush()
                uow.triage_results.add(self._ids.next_id("result"), execution_id, decision.result)
                uow.executions.replace(
                    existing.model_copy(update={"state": terminal, "updated_at": self._clock.now()})
                )
                uow.audit.append(
                    self._audit(
                        "triage.policy_enforced",
                        execution_id,
                        correlation_id,
                        {
                            "policy_version": decision.policy_version,
                            "reason_codes": [item.value for item in decision.reason_codes],
                            "orchestration_reason": reason.value,
                            "disposition": decision.result.disposition.value,
                        },
                    )
                )
                uow.audit.append(
                    self._audit(
                        "triage.execution_terminal",
                        execution_id,
                        correlation_id,
                        {"state": terminal.value},
                    )
                )
                uow.commit()
            return True
        except Exception:
            return False

    def _safe_policy_decision(
        self, alert: SecurityAlert, scope: AuthorizedActionScope
    ) -> PolicyDecision:
        return self._policy.evaluate_untrusted(
            {"invalid": "orchestration-safe-review"},
            alert_id=alert.alert_id,
            action_scope=scope,
            timestamp=self._clock.now(),
        )

    def _to_evidence(
        self, invocation: ToolInvocationRecord, outcome: dict[str, object]
    ) -> AccumulatedEvidence:
        provenance = outcome.get("provenance")
        provenance_data = provenance if isinstance(provenance, dict) else {}
        tool_version = str(provenance_data.get("tool_version", "unknown"))
        source_version = str(provenance_data.get("fixture_version", "unknown"))
        status = str(outcome.get("status", "UNKNOWN"))
        call = ToolCallReference(
            invocation_id=invocation.call_id,
            tool_name=invocation.tool_name,
            tool_version=tool_version,
            called_at=invocation.started_at,
            summary=f"{invocation.tool_name} returned {status}.",
        )
        reference = EvidenceReference(
            evidence_id=self._ids.next_id("evidence"),
            source_type=invocation.tool_name,
            source_reference=invocation.call_id,
            collected_at=invocation.completed_at,
            source_version=source_version,
            summary=f"Sanitized {invocation.tool_name} outcome: {status}.",
            tool_invocation_id=invocation.call_id,
        )
        return AccumulatedEvidence(reference=reference, tool_call=call, outcome=outcome)

    @staticmethod
    def _candidate_references_are_valid(
        candidate: CandidateAssessment, accumulated: list[AccumulatedEvidence]
    ) -> bool:
        evidence = {item.reference.evidence_id: item.reference for item in accumulated}
        calls = {item.tool_call.invocation_id: item.tool_call for item in accumulated}
        return all(evidence.get(item.evidence_id) == item for item in candidate.evidence) and all(
            calls.get(item.invocation_id) == item for item in candidate.tool_calls
        )

    def _audit(
        self,
        event_type: str,
        execution_id: str,
        correlation_id: str,
        data: dict[str, Any],
        *,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
    ) -> AuditEvent:
        return AuditEvent(
            event_id=self._ids.next_id("audit"),
            event_type=event_type,
            occurred_at=self._clock.now(),
            execution_id=execution_id,
            correlation_id=correlation_id,
            actor_id="system-orchestrator",
            target_type="triage_execution",
            target_id=execution_id,
            data=data,
            outcome=outcome,
        )

    @staticmethod
    def _persistence_failure(execution_id: str, correlation_id: str) -> OrchestrationOutcome:
        return OrchestrationOutcome(
            execution_id=execution_id,
            correlation_id=correlation_id,
            durable=False,
            reason_code=OrchestrationReasonCode.PERSISTENCE_FAILURE,
        )
