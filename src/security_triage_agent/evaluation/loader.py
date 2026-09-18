"""Strict evaluation-suite loading and trusted reference validation."""

from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from security_triage_agent.adapters.tools.fixture_models import FixtureDataset
from security_triage_agent.application.action_catalog import ActionCatalog
from security_triage_agent.application.tool_registry import ToolRegistry
from security_triage_agent.evaluation.schema import EvaluationManifest, EvaluationScenario

SUPPORTED_EVALUATION_SCHEMA = "1.0"


class EvaluationValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class EvaluationSuite:
    schema_version: str
    suite_version: str
    fixture_version: str
    scenarios: tuple[EvaluationScenario, ...]

    def get(self, scenario_id: str) -> EvaluationScenario:
        for scenario in self.scenarios:
            if scenario.scenario_id == scenario_id:
                return scenario
        raise EvaluationValidationError("unknown scenario identifier")


def load_suite(
    path: Path,
    *,
    fixtures: FixtureDataset,
    registry: ToolRegistry,
    catalog: ActionCatalog,
) -> EvaluationSuite:
    try:
        manifest = EvaluationManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError) as error:
        raise EvaluationValidationError("evaluation suite loading failed") from error
    if manifest.schema_version != SUPPORTED_EVALUATION_SCHEMA:
        raise EvaluationValidationError("unsupported evaluation schema version")
    if manifest.fixture_version != fixtures.manifest.fixture_version:
        raise EvaluationValidationError("evaluation fixture version mismatch")
    scenarios = tuple(sorted(manifest.scenarios, key=lambda item: item.scenario_id))
    ids = [item.scenario_id for item in scenarios]
    if len(ids) != len(set(ids)):
        raise EvaluationValidationError("duplicate scenario identifier")
    alerts = {item.alert_id: item for item in fixtures.alerts}
    tool_ids = set(registry)
    action_ids = set(catalog)
    for scenario in scenarios:
        if scenario.alert_id not in alerts:
            raise EvaluationValidationError("scenario references unknown alert")
        if not alerts[scenario.alert_id].source.startswith("synthetic-"):
            raise EvaluationValidationError("evaluation alert is not synthetic")
        if (
            not (
                set(scenario.required_tools)
                | set(scenario.allowed_tools)
                | set(scenario.forbidden_tools)
            )
            <= tool_ids
        ):
            raise EvaluationValidationError("scenario references unknown tool")
        if (
            not (set(scenario.expected_actions) | set(scenario.expected_approval_actions))
            <= action_ids
        ):
            raise EvaluationValidationError("scenario references unknown action")
    return EvaluationSuite(
        schema_version=manifest.schema_version,
        suite_version=manifest.suite_version,
        fixture_version=manifest.fixture_version,
        scenarios=scenarios,
    )
