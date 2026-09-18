"""End-to-end deterministic evaluation runner and persistence tests."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import func, select

from security_triage_agent.adapters.persistence.models import (
    ActionExecutionRow,
    ApprovalDecisionRow,
)
from security_triage_agent.adapters.persistence.uow import create_engine
from security_triage_agent.adapters.tools.fixture_models import FixtureDataset
from security_triage_agent.application.orchestration_contracts import ReasonerContext
from security_triage_agent.bootstrap import build_evaluation_runner
from security_triage_agent.config import Environment, Settings
from security_triage_agent.evaluation.persistence import EvaluationRunRecord
from security_triage_agent.evaluation.reporting import render_json, render_text
from security_triage_agent.evaluation.runner import EvaluationReport, EvaluationRunner


def settings(tmp_path: Path, fixture_root: Path) -> Settings:
    database = tmp_path / "evaluation.db"
    database.parent.mkdir(parents=True, exist_ok=True)
    config = Config("alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    command.upgrade(config, "head")
    return Settings(
        environment=Environment.TEST,
        database_url=f"sqlite:///{database}",
        fixture_path=str(fixture_root),
        evaluation_path=str(fixture_root.parents[1] / "evaluations/v1/manifest.json"),
    )


def material(report: EvaluationReport) -> tuple[dict[str, object], ...]:
    return tuple(
        case.score.model_dump(exclude={"duration_ms"})
        for case in sorted(report.cases, key=lambda item: item.scenario_id)
    )


def test_full_suite_runs_same_bounded_path_and_persists(tmp_path: Path, fixture_root: Path) -> None:
    configured = settings(tmp_path, fixture_root)
    runner = build_evaluation_runner(configured)
    report = runner.run()
    assert report.aggregate.scenario_count == 10
    assert report.aggregate.exact_count == 6
    assert report.aggregate.acceptable_count == 3
    assert report.aggregate.failure_count == 1
    assert report.aggregate.false_positives == 0
    assert report.aggregate.false_negatives == 0
    assert report.aggregate.required_tool_omissions == 0
    assert report.aggregate.forbidden_tool_calls == 0
    assert "NEEDS_REVIEW" in str(report.aggregate.confusion_matrix)
    assert all(case.score.total_tool_calls == 1 for case in report.cases)
    assert all(case.score.completed_durably for case in report.cases)

    with runner._uow_factory() as uow:
        stored = uow.evaluations.get_run(report.run_id)
        cases = uow.evaluations.list_cases(report.run_id)
    assert stored is not None
    assert stored.reasoner_label == "deterministic-demo-v1"
    assert stored.policy_version == "1.0.0"
    assert stored.fixture_version == "v1"
    assert len(cases) == 10

    engine = create_engine(configured.database_url)
    with engine.connect() as connection:
        assert connection.scalar(select(func.count()).select_from(ApprovalDecisionRow)) == 0
        assert connection.scalar(select(func.count()).select_from(ActionExecutionRow)) == 0

    text = render_text(report)
    assert "not a calibrated probability" in text
    assert "Confusion matrix" in text
    assert '"suite_version":"v1"' in render_json(report).replace(" ", "").replace("\n", "")


def test_single_scenario_and_restart_reconstruction(tmp_path: Path, fixture_root: Path) -> None:
    configured = settings(tmp_path, fixture_root)
    report = build_evaluation_runner(configured).run("typed-not-found-evidence")
    assert len(report.cases) == 1
    assert report.cases[0].score.actual_disposition is not None
    assert report.cases[0].score.actual_disposition.value == "NEEDS_REVIEW"
    assert report.cases[0].score.successful_tool_calls == 1
    reopened = build_evaluation_runner(configured)
    with reopened._uow_factory() as uow:
        stored = uow.evaluations.get_run(report.run_id)
        cases = uow.evaluations.list_cases(report.run_id)
    assert stored == EvaluationRunRecord.model_validate(report.model_dump(exclude={"cases"}))
    assert cases[0].score == report.cases[0].score


def test_repeated_runs_have_equivalent_material_scores(tmp_path: Path, fixture_root: Path) -> None:
    first_settings = settings(tmp_path / "first", fixture_root)
    second_settings = settings(tmp_path / "second", fixture_root)
    first = build_evaluation_runner(first_settings).run()
    second = build_evaluation_runner(second_settings).run()
    assert material(first) == material(second)


def test_reasoner_context_has_no_ground_truth_fields(fixture_dataset: FixtureDataset) -> None:
    forbidden = {
        "expected_disposition",
        "expected_actions",
        "expected_tools",
        "expected_escalation",
        "scoring_rubric",
        "ground_truth_rationale",
    }
    assert forbidden.isdisjoint(ReasonerContext.model_fields)
    isolated = EvaluationRunner._isolated_alert(
        fixture_dataset.alerts[0], "benign-secret-ground-truth"
    )
    assert "benign-secret-ground-truth" not in isolated.model_dump_json()
