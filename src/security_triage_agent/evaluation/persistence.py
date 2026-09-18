"""Framework-independent persisted evaluation records."""

from security_triage_agent.domain._base import DomainModel, Identifier, UtcDatetime, Version
from security_triage_agent.evaluation.scoring import EvaluationAggregate, EvaluationCaseScore


class EvaluationRunRecord(DomainModel):
    run_id: Identifier
    suite_version: Version
    schema_version: Version
    fixture_version: Version
    policy_version: Version
    reasoner_label: Identifier
    reasoner_implementation: Identifier
    provider: Identifier
    model: Identifier
    prompt_version: Version
    application_version: Version
    started_at: UtcDatetime
    completed_at: UtcDatetime
    aggregate: EvaluationAggregate


class EvaluationCaseRecord(DomainModel):
    case_id: Identifier
    run_id: Identifier
    scenario_id: Identifier
    scenario_version: Version
    triage_execution_id: Identifier
    score: EvaluationCaseScore
