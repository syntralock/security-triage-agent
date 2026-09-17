"""Shared behavioral contract for every fixture-backed evidence tool."""

from dataclasses import dataclass
from typing import Any

import pytest
from pydantic import BaseModel

from security_triage_agent.adapters.tools.fixture_models import FixtureDataset
from security_triage_agent.adapters.tools.fixtures import (
    FixtureDeviceContextTool,
    FixtureIdentityContextTool,
    FixtureIpReputationTool,
    FixtureMfaEventsTool,
    FixtureRecentSignInsTool,
    FixtureRelatedAlertsTool,
    FixtureUserRiskTool,
)
from security_triage_agent.application.evidence_tools import (
    DeviceRequest,
    IpAddressRequest,
    UserRequest,
)
from security_triage_agent.application.ports.tools import (
    DataClassification,
    EvidenceTool,
    ToolAccess,
    ToolStatus,
)


@dataclass(frozen=True)
class ToolCase:
    tool: EvidenceTool[Any, Any]
    found_request: BaseModel
    missing_request: BaseModel


@pytest.fixture
def tool_cases(fixture_dataset: FixtureDataset) -> tuple[ToolCase, ...]:
    return (
        ToolCase(
            FixtureRecentSignInsTool(fixture_dataset),
            UserRequest(user_id="user-alex"),
            UserRequest(user_id="user-missing"),
        ),
        ToolCase(
            FixtureUserRiskTool(fixture_dataset),
            UserRequest(user_id="user-riley"),
            UserRequest(user_id="user-missing"),
        ),
        ToolCase(
            FixtureDeviceContextTool(fixture_dataset),
            DeviceRequest(device_id="device-alex-laptop"),
            DeviceRequest(device_id="device-missing"),
        ),
        ToolCase(
            FixtureIpReputationTool(fixture_dataset),
            IpAddressRequest(ip_address="198.51.100.10"),
            IpAddressRequest(ip_address="192.0.2.254"),
        ),
        ToolCase(
            FixtureMfaEventsTool(fixture_dataset),
            UserRequest(user_id="user-riley"),
            UserRequest(user_id="user-missing"),
        ),
        ToolCase(
            FixtureRelatedAlertsTool(fixture_dataset),
            UserRequest(user_id="user-riley"),
            UserRequest(user_id="user-missing"),
        ),
        ToolCase(
            FixtureIdentityContextTool(fixture_dataset),
            UserRequest(user_id="user-alex"),
            UserRequest(user_id="user-missing"),
        ),
    )


def test_all_tool_metadata_is_complete_and_read_only(tool_cases: tuple[ToolCase, ...]) -> None:
    names: set[str] = set()
    for case in tool_cases:
        metadata = case.tool.metadata
        names.add(metadata.name)
        assert metadata.version == "1.0.0"
        assert metadata.access is ToolAccess.READ_ONLY
        assert metadata.data_classification is DataClassification.SYNTHETIC_DEMO
        assert metadata.timeout_ms > 0
        assert metadata.input_schema["type"] == "object"
        assert metadata.output_schema["type"] == "object"

    assert names == {
        "get_recent_signins",
        "get_user_risk",
        "get_device_context",
        "get_ip_reputation",
        "get_mfa_events",
        "find_related_alerts",
        "get_identity_context",
    }


def test_all_tools_are_deterministic_and_serializable(tool_cases: tuple[ToolCase, ...]) -> None:
    for case in tool_cases:
        first = case.tool.execute(case.found_request)
        second = case.tool.execute(case.found_request)

        assert first.status is ToolStatus.FOUND
        assert first == second
        assert first.model_dump_json() == second.model_dump_json()
        assert type(first).model_validate_json(first.model_dump_json()) == first
        assert first.provenance.tool_name == case.tool.metadata.name
        assert first.provenance.tool_version == case.tool.metadata.version
        assert first.provenance.fixture_version == "v1"


def test_all_tools_return_typed_not_found_outcomes(tool_cases: tuple[ToolCase, ...]) -> None:
    for case in tool_cases:
        result = case.tool.execute(case.missing_request)

        assert result.status is ToolStatus.NOT_FOUND
        assert result.identifier
        assert result.resource_type
        assert result.provenance.fixture_version == "v1"
        assert "not found" in result.message.lower()
        assert type(result).model_validate_json(result.model_dump_json()) == result
