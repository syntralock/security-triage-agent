"""Human- and machine-readable deterministic evaluation reports."""

import json

from security_triage_agent.evaluation.runner import EvaluationReport


def render_text(report: EvaluationReport) -> str:
    aggregate = report.aggregate
    lines = [
        f"Evaluation suite {report.suite_version} / run {report.run_id}",
        (
            f"Reasoner: {report.reasoner_label}; policy: {report.policy_version}; "
            f"fixture: {report.fixture_version}"
        ),
        (
            f"Scenarios: {aggregate.scenario_count}; exact: {aggregate.exact_count}; "
            f"acceptable: {aggregate.acceptable_count}; failures: {aggregate.failure_count}"
        ),
        (
            f"FP: {aggregate.false_positives}/{aggregate.non_malicious_ground_truth_count}; "
            f"FN: {aggregate.false_negatives}/{aggregate.malicious_ground_truth_count}"
        ),
        (
            f"Tools: {aggregate.total_tool_calls} calls; "
            f"required omitted: {aggregate.required_tool_omissions}; "
            f"forbidden: {aggregate.forbidden_tool_calls}"
        ),
        "Confusion matrix: " + json.dumps(aggregate.confusion_matrix, sort_keys=True),
        "Cases:",
    ]
    for case in report.cases:
        score = case.score
        lines.append(
            f"- {case.scenario_id}: {score.disposition_status}; "
            f"actual={score.actual_disposition}; escalation={score.escalation_match}; "
            f"reason={score.orchestration_reason}; duration_ms={score.duration_ms}"
        )
    lines.append("Warning: model-reported confidence is not a calibrated probability.")
    return "\n".join(lines)


def render_json(report: EvaluationReport) -> str:
    return report.model_dump_json(indent=2)
