"""Offline runner that uses the production orchestration, gateway, and policy path."""

import hashlib
from collections.abc import Callable

from security_triage_agent.application.orchestrator import TriageOrchestrator
from security_triage_agent.application.ports.reasoner import Clock, IdentifierGenerator
from security_triage_agent.application.ports.repositories import UnitOfWork
from security_triage_agent.domain.alerts import SecurityAlert, SourcePayloadReference
from security_triage_agent.evaluation.loader import EvaluationSuite
from security_triage_agent.evaluation.persistence import EvaluationCaseRecord, EvaluationRunRecord
from security_triage_agent.evaluation.schema import EvaluationScenario
from security_triage_agent.evaluation.scoring import aggregate_scores, score_case


class EvaluationReport(EvaluationRunRecord):
    cases: tuple[EvaluationCaseRecord, ...]


class EvaluationRunner:
    def __init__(
        self,
        *,
        suite: EvaluationSuite,
        alerts: tuple[SecurityAlert, ...],
        orchestrator: TriageOrchestrator,
        uow_factory: Callable[[], UnitOfWork],
        clock: Clock,
        identifiers: IdentifierGenerator,
        reasoner_label: str,
        policy_version: str,
        application_version: str,
    ) -> None:
        self._suite = suite
        self._alerts = {item.alert_id: item for item in alerts}
        self._orchestrator = orchestrator
        self._uow_factory = uow_factory
        self._clock = clock
        self._ids = identifiers
        self._reasoner_label = reasoner_label
        self._policy_version = policy_version
        self._application_version = application_version

    def run(self, scenario_id: str | None = None) -> EvaluationReport:
        scenarios = (
            (self._suite.get(scenario_id),) if scenario_id is not None else self._suite.scenarios
        )
        run_id = self._ids.next_id("evaluation-run")
        started_at = self._clock.now()
        case_records = tuple(self._run_case(run_id, scenario) for scenario in scenarios)
        completed_at = self._clock.now()
        run = EvaluationRunRecord(
            run_id=run_id,
            suite_version=self._suite.suite_version,
            schema_version=self._suite.schema_version,
            fixture_version=self._suite.fixture_version,
            policy_version=self._policy_version,
            reasoner_label=self._reasoner_label,
            application_version=self._application_version,
            started_at=started_at,
            completed_at=completed_at,
            aggregate=aggregate_scores(tuple(item.score for item in case_records)),
        )
        with self._uow_factory() as uow:
            uow.evaluations.add_run(run)
            uow.flush()
            for case in case_records:
                uow.evaluations.add_case(case)
            uow.commit()
        return EvaluationReport(**run.model_dump(), cases=case_records)

    def _run_case(self, run_id: str, scenario: EvaluationScenario) -> EvaluationCaseRecord:
        alert = self._isolated_alert(self._alerts[scenario.alert_id], scenario.scenario_id)
        execution_id = self._ids.next_id("evaluation-execution")
        before = self._clock.monotonic_ms()
        outcome = self._orchestrator.run(
            alert,
            idempotency_key=f"{run_id}:{scenario.scenario_id}",
            execution_id=execution_id,
            correlation_id=self._ids.next_id("evaluation-correlation"),
        )
        duration_ms = max(0, self._clock.monotonic_ms() - before)
        with self._uow_factory() as uow:
            tools = uow.tool_invocations.list_for_execution(outcome.execution_id)
        return EvaluationCaseRecord(
            case_id=self._ids.next_id("evaluation-case"),
            run_id=run_id,
            scenario_id=scenario.scenario_id,
            scenario_version=scenario.scenario_version,
            triage_execution_id=outcome.execution_id,
            score=score_case(scenario, outcome, tools, duration_ms),
        )

    @staticmethod
    def _isolated_alert(alert: SecurityAlert, scenario_id: str) -> SecurityAlert:
        scenario_digest = hashlib.sha256(scenario_id.encode()).hexdigest()
        payload_digest = hashlib.sha256(
            f"{alert.original_payload.payload_digest}:{scenario_id}".encode()
        ).hexdigest()
        return alert.model_copy(
            update={
                "alert_id": f"eval-alert-{scenario_digest[:24]}",
                "original_payload": SourcePayloadReference(
                    reference_id=f"eval-payload-{scenario_digest[:24]}",
                    payload_digest=f"sha256:{payload_digest}",
                ),
            }
        )
