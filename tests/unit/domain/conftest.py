"""Synthetic factories shared by domain contract tests."""

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from security_triage_agent.domain.actions import ActionProposal
from security_triage_agent.domain.entities import UserEntityReference
from security_triage_agent.domain.evidence import EvidenceReference, ToolCallReference
from security_triage_agent.domain.triage import Disposition, Severity, TriageResult


@pytest.fixture
def occurred_at() -> datetime:
    return datetime(2026, 1, 15, 12, 0, tzinfo=UTC)


@pytest.fixture
def action_factory() -> Callable[..., ActionProposal]:
    def factory(**overrides: object) -> ActionProposal:
        values: dict[str, object] = {
            "action_id": "action-001",
            "catalog_action_id": "require-password-reset",
            "target": UserEntityReference(identifier="user-001"),
            "parameters": {"invalidate_sessions": True, "channels": ["web", "mobile"]},
            "rationale": "Synthetic suspicious sign-in requires analyst review.",
        }
        values.update(overrides)
        return ActionProposal.model_validate(values)

    return factory


@pytest.fixture
def triage_result_factory(
    occurred_at: datetime,
    action_factory: Callable[..., ActionProposal],
) -> Callable[..., TriageResult]:
    def factory(**overrides: object) -> TriageResult:
        tool = ToolCallReference(
            invocation_id="tool-call-001",
            tool_name="get-user-risk",
            tool_version="1.0",
            called_at=occurred_at,
            summary="Synthetic user risk was elevated.",
        )
        evidence = EvidenceReference(
            evidence_id="evidence-001",
            source_type="user-risk",
            source_reference="fixture-user-risk-001",
            collected_at=occurred_at,
            source_version="1.0",
            summary="Synthetic user risk was elevated.",
            tool_invocation_id=tool.invocation_id,
        )
        action = action_factory()
        values: dict[str, object] = {
            "alert_id": "alert-001",
            "disposition": Disposition.SUSPICIOUS,
            "confidence": Decimal("0.873421"),
            "severity": Severity.HIGH,
            "evidence": (evidence,),
            "reasoning_summary": "Correlated synthetic evidence supports analyst review.",
            "recommended_actions": (action,),
            "actions_requiring_approval": (),
            "escalation_required": True,
            "escalation_reason": "A human should validate the proposed high-impact response.",
            "tool_calls": (tool,),
            "timestamp": occurred_at,
        }
        values.update(overrides)
        return TriageResult.model_validate(values)

    return factory
