"""Mocked-provider evaluation integration through the production OpenAI adapter."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

from alembic import command
from alembic.config import Config
from sqlalchemy import func, select

import security_triage_agent.bootstrap as bootstrap
from security_triage_agent.adapters.persistence.models import (
    ActionExecutionRow,
    ApprovalDecisionRow,
)
from security_triage_agent.adapters.persistence.uow import create_engine
from security_triage_agent.adapters.reasoners.openai import (
    V2_PROMPT_VERSION,
    OpenAIReasoner,
    OpenAIV2ReasonerOutput,
)
from security_triage_agent.config import Environment, ReasonerProvider, Settings
from security_triage_agent.domain.states import TriageExecutionState


class ScenarioResponses:
    def __init__(self, failure: Exception | None = None) -> None:
        self.failure = failure
        self.inputs: list[str] = []

    def parse(self, **kwargs: object) -> object:
        if self.failure is not None:
            raise self.failure
        serialized = str(kwargs["input"])
        self.inputs.append(serialized)
        context = json.loads(serialized)
        if not context["evidence"]:
            user = next(
                item for item in context["alert"]["entities"] if item["entity_type"] == "USER"
            )
            parsed: dict[str, Any] = {
                "step": {
                    "step_type": "TOOL_CALL",
                    "tool_name": "get_user_risk",
                    "arguments": {"user_id": user["identifier"]},
                }
            }
            if kwargs["text_format"] is OpenAIV2ReasonerOutput:
                parsed["step"]["evidence_goal"] = (
                    "Determine whether identity risk materially changes the assessment."
                )
        else:
            evidence = context["evidence"]
            parsed = {
                "step": {
                    "step_type": "CANDIDATE",
                    "candidate": {
                        "disposition": "NEEDS_REVIEW",
                        "severity": context["alert"]["source_severity"],
                        "confidence": "0.5",
                        "evidence_reference_ids": [
                            item["reference"]["evidence_id"] for item in evidence
                        ],
                        "reasoning_summary": "Mocked provider used supplied synthetic evidence.",
                        "recommended_actions": [],
                        "escalation_required": True,
                        "escalation_reason": "Mocked provider requested review.",
                        "tool_call_reference_ids": [
                            item["tool_call"]["invocation_id"] for item in evidence
                        ],
                    },
                }
            }
        return SimpleNamespace(
            output_parsed=parsed,
            usage=SimpleNamespace(input_tokens=50, output_tokens=25),
        )


def configured_settings(
    tmp_path: Path,
    fixture_root: Path,
    *,
    prompt_version: Literal["openai-l1-v1", "openai-l1-v2"] = "openai-l1-v1",
) -> Settings:
    database = tmp_path / f"openai-evaluation-{prompt_version}.db"
    config = Config("alembic.ini")
    config.attributes["database_url"] = f"sqlite:///{database}"
    command.upgrade(config, "head")
    return Settings(
        _env_file=None,
        environment=Environment.TEST,
        database_url=f"sqlite:///{database}",
        fixture_path=str(fixture_root),
        evaluation_path=str(fixture_root.parents[1] / "evaluations/v1/manifest.json"),
        reasoner_provider=ReasonerProvider.OPENAI,
        openai_api_key="synthetic-test-key",  # pragma: allowlist secret
        openai_model="mocked-model",
        openai_prompt_version=prompt_version,
    )


def test_openai_reasoner_uses_same_runner_and_records_identity(
    tmp_path: Path, fixture_root: Path, monkeypatch: Any
) -> None:
    provider = ScenarioResponses()

    def build_mocked(
        *,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_output_tokens: int,
        prompt_version: str,
    ) -> OpenAIReasoner:
        return OpenAIReasoner(
            api_key=api_key,
            model=model,
            timeout_seconds=timeout_seconds,
            max_output_tokens=max_output_tokens,
            prompt_version=prompt_version,
            client=SimpleNamespace(responses=provider),
        )

    monkeypatch.setattr(bootstrap, "OpenAIReasoner", build_mocked)
    settings = configured_settings(tmp_path, fixture_root)
    runner = bootstrap.build_evaluation_runner(settings)
    report = runner.run("typed-not-found-evidence")
    assert report.reasoner_implementation == "OpenAIReasoner"
    assert report.provider == "openai"
    assert report.model == "mocked-model"
    assert report.prompt_version == "openai-l1-v1"
    assert report.aggregate.scenario_count == 1
    assert report.cases[0].score.successful_tool_calls == 1
    assert all("ground_truth" not in item for item in provider.inputs)

    with runner._uow_factory() as uow:
        execution = uow.executions.get(report.cases[0].triage_execution_id)
        result = uow.triage_results.get_for_execution(report.cases[0].triage_execution_id)
    assert execution is not None and execution.state is TriageExecutionState.NEEDS_REVIEW
    assert result is not None
    assert len(result.evidence) == 1
    assert result.evidence[0].evidence_id.startswith("evidence-")
    assert result.tool_calls[0].invocation_id.startswith("tool-invocation-")

    engine = create_engine(settings.database_url)
    with engine.connect() as connection:
        assert connection.scalar(select(func.count()).select_from(ApprovalDecisionRow)) == 0
        assert connection.scalar(select(func.count()).select_from(ActionExecutionRow)) == 0


def test_openai_requires_explicit_key(tmp_path: Path, fixture_root: Path) -> None:
    settings = configured_settings(tmp_path, fixture_root).model_copy(
        update={"openai_api_key": None}
    )
    try:
        bootstrap.build_evaluation_runner(settings)
    except RuntimeError as exc:
        assert str(exc) == "OpenAI reasoner is enabled but OPENAI_API_KEY is not configured"
    else:
        raise AssertionError("OpenAI configuration without a key must fail closed")


def test_provider_failure_is_measured_as_safe_review(
    tmp_path: Path, fixture_root: Path, monkeypatch: Any
) -> None:
    provider = ScenarioResponses(failure=RuntimeError("sensitive provider detail"))

    def build_failing(
        *,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_output_tokens: int,
        prompt_version: str,
    ) -> OpenAIReasoner:
        return OpenAIReasoner(
            api_key=api_key,
            model=model,
            timeout_seconds=timeout_seconds,
            max_output_tokens=max_output_tokens,
            prompt_version=prompt_version,
            client=SimpleNamespace(responses=provider),
        )

    monkeypatch.setattr(bootstrap, "OpenAIReasoner", build_failing)
    report = bootstrap.build_evaluation_runner(configured_settings(tmp_path, fixture_root)).run(
        "typed-not-found-evidence"
    )
    score = report.cases[0].score
    assert score.completed_durably is True
    assert score.actual_disposition is not None
    assert score.actual_disposition.value == "NEEDS_REVIEW"
    assert score.total_tool_calls == 0
    assert report.provider == "openai"


def test_v2_runs_through_production_wiring_with_scope_and_action_semantics(
    tmp_path: Path, fixture_root: Path, monkeypatch: Any
) -> None:
    provider = ScenarioResponses()

    def build_mocked(
        *,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_output_tokens: int,
        prompt_version: str,
    ) -> OpenAIReasoner:
        return OpenAIReasoner(
            api_key=api_key,
            model=model,
            timeout_seconds=timeout_seconds,
            max_output_tokens=max_output_tokens,
            prompt_version=prompt_version,
            client=SimpleNamespace(responses=provider),
        )

    monkeypatch.setattr(bootstrap, "OpenAIReasoner", build_mocked)
    settings = configured_settings(tmp_path, fixture_root, prompt_version="openai-l1-v2")

    report = bootstrap.build_evaluation_runner(settings).run("typed-not-found-evidence")

    assert report.prompt_version == V2_PROMPT_VERSION
    assert report.aggregate.scenario_count == 1
    assert provider.inputs
    for serialized in provider.inputs:
        supplied = json.loads(serialized)
        assert supplied["authorized_tool_targets"]
        assert len(supplied["action_semantics"]) == 6
        assert all(item["target_types"] for item in supplied["action_semantics"])
        assert "ground_truth" not in serialized
        assert "original_payload" not in supplied["alert"]
