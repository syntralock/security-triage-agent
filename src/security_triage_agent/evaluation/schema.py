"""Strict trusted-data contracts for versioned evaluation scenarios."""

from enum import StrEnum

from pydantic import Field, model_validator

from security_triage_agent.domain._base import DomainModel, Identifier, NonEmptyText, Version
from security_triage_agent.domain.triage import Disposition, Severity


class BinaryLabel(StrEnum):
    MALICIOUS = "MALICIOUS"
    NON_MALICIOUS = "NON_MALICIOUS"
    AMBIGUOUS = "AMBIGUOUS"


class EvaluationScenario(DomainModel):
    scenario_id: Identifier
    scenario_version: Version
    description: NonEmptyText
    alert_id: Identifier
    allowed_dispositions: tuple[Disposition, ...] = Field(min_length=1)
    expected_escalation: bool
    required_tools: tuple[Identifier, ...] = ()
    allowed_tools: tuple[Identifier, ...] = ()
    forbidden_tools: tuple[Identifier, ...] = ()
    expected_actions: tuple[Identifier, ...] = ()
    expected_approval_actions: tuple[Identifier, ...] = ()
    binary_label: BinaryLabel
    expected_assessed_severity: Severity
    tags: tuple[Identifier, ...] = ()
    ground_truth_rationale: NonEmptyText

    @model_validator(mode="after")
    def validate_sets(self) -> "EvaluationScenario":
        for label, values in (
            ("allowed dispositions", self.allowed_dispositions),
            ("required tools", self.required_tools),
            ("allowed tools", self.allowed_tools),
            ("forbidden tools", self.forbidden_tools),
            ("expected actions", self.expected_actions),
            ("expected approval actions", self.expected_approval_actions),
            ("tags", self.tags),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"duplicate {label}")
        if not set(self.required_tools) <= set(self.allowed_tools):
            raise ValueError("required tools must be allowed")
        if set(self.allowed_tools) & set(self.forbidden_tools):
            raise ValueError("allowed and forbidden tools must be disjoint")
        if not set(self.expected_approval_actions) <= set(self.expected_actions):
            raise ValueError("approval actions must be expected actions")
        return self


class EvaluationManifest(DomainModel):
    schema_version: Version
    suite_version: Version
    fixture_version: Version
    scenarios: tuple[EvaluationScenario, ...] = Field(min_length=1)
