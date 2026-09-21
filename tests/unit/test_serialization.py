"""Safe JSON serialization preserves immutable action-domain semantics."""

import json
from types import MappingProxyType

from security_triage_agent.domain.actions import ActionRecommendation
from security_triage_agent.serialization import safe_json_dumps


def test_immutable_action_parameters_are_explicitly_json_serializable() -> None:
    recommendation = ActionRecommendation.model_validate(
        {
            "catalog_action_id": "delete_email",
            "target": {"entity_type": "USER", "identifier": "user-alex"},
            "parameters": {"message_id": "message-synthetic-001", "nested": ["one"]},
            "rationale": "Synthetic serialization regression.",
        }
    )
    assert isinstance(recommendation.parameters, MappingProxyType)

    payload = json.loads(safe_json_dumps({"action": recommendation}))
    assert payload["action"]["parameters"] == {
        "message_id": "message-synthetic-001",
        "nested": ["one"],
    }
