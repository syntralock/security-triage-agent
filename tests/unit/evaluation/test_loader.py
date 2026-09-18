"""Strict evaluation-suite validation tests."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from security_triage_agent.adapters.tools import (
    FixtureDeviceContextTool,
    FixtureIdentityContextTool,
    FixtureIpReputationTool,
    FixtureMfaEventsTool,
    FixtureRecentSignInsTool,
    FixtureRelatedAlertsTool,
    FixtureUserRiskTool,
)
from security_triage_agent.adapters.tools.fixture_models import FixtureDataset
from security_triage_agent.application.action_catalog import initial_action_catalog
from security_triage_agent.application.tool_registry import ToolRegistry
from security_triage_agent.evaluation.loader import (
    EvaluationSuite,
    EvaluationValidationError,
    load_suite,
)


def registry(dataset: FixtureDataset) -> ToolRegistry:
    return ToolRegistry(
        (
            FixtureRecentSignInsTool(dataset),
            FixtureUserRiskTool(dataset),
            FixtureDeviceContextTool(dataset),
            FixtureIpReputationTool(dataset),
            FixtureMfaEventsTool(dataset),
            FixtureRelatedAlertsTool(dataset),
            FixtureIdentityContextTool(dataset),
        )
    )


def load(path: Path, dataset: FixtureDataset) -> EvaluationSuite:
    return load_suite(
        path,
        fixtures=dataset,
        registry=registry(dataset),
        catalog=initial_action_catalog(),
    )


def mutate_manifest(tmp_path: Path, source: Path, change: Callable[[dict[str, Any]], None]) -> Path:
    data = json.loads(source.read_text())
    change(data)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data))
    return path


def test_valid_suite_loads_in_stable_order(
    fixture_dataset: FixtureDataset, fixture_root: Path
) -> None:
    suite = load(fixture_root.parents[1] / "evaluations/v1/manifest.json", fixture_dataset)
    assert len(suite.scenarios) == 10
    assert [item.scenario_id for item in suite.scenarios] == sorted(
        item.scenario_id for item in suite.scenarios
    )


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda data: data.update(schema_version="9.9"), "unsupported evaluation schema"),
        (
            lambda data: data["scenarios"].append(data["scenarios"][0]),
            "duplicate scenario",
        ),
        (
            lambda data: data["scenarios"][0].update(alert_id="missing-alert"),
            "unknown alert",
        ),
        (
            lambda data: data["scenarios"][0].update(required_tools=["unknown_tool"]),
            "loading failed",
        ),
        (
            lambda data: data["scenarios"][0].update(expected_actions=["unknown_action"]),
            "unknown action",
        ),
        (lambda data: data.update(fixture_version="v99"), "fixture version mismatch"),
        (
            lambda data: data["scenarios"][0].update(allowed_dispositions=["CERTAIN"]),
            "loading failed",
        ),
        (
            lambda data: data["scenarios"][0].update(expected_escalation="sometimes"),
            "loading failed",
        ),
    ],
)
def test_invalid_suite_is_rejected(
    tmp_path: Path,
    fixture_dataset: FixtureDataset,
    fixture_root: Path,
    change: Callable[[dict[str, Any]], None],
    message: str,
) -> None:
    path = mutate_manifest(
        tmp_path, fixture_root.parents[1] / "evaluations/v1/manifest.json", change
    )
    with pytest.raises(EvaluationValidationError, match=message):
        load(path, fixture_dataset)
