"""Security alert and normalized entity contract tests."""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import TypeAdapter, ValidationError

from security_triage_agent.domain.alerts import SecurityAlert, SourcePayloadReference
from security_triage_agent.domain.entities import (
    DeviceEntityReference,
    EntityReference,
    EntityType,
    IpAddressEntityReference,
    UserEntityReference,
)
from security_triage_agent.domain.triage import Severity


def make_alert(occurred_at: datetime, **overrides: object) -> SecurityAlert:
    values: dict[str, object] = {
        "alert_id": "alert-001",
        "source": "synthetic-entra",
        "source_severity": Severity.MEDIUM,
        "title": "Synthetic risky sign-in",
        "description": "Untrusted descriptive content remains inert data.",
        "occurred_at": occurred_at,
        "detected_at": occurred_at + timedelta(minutes=2),
        "entities": (
            UserEntityReference(identifier="user-001"),
            DeviceEntityReference(identifier="device-001"),
            IpAddressEntityReference(identifier="192.0.2.10"),
        ),
        "provider_schema_version": "2026-01",
        "original_payload": SourcePayloadReference(
            reference_id="payload-001",
            payload_digest=f"sha256:{'a' * 64}",
        ),
    }
    values.update(overrides)
    return SecurityAlert.model_validate(values)


def test_alert_preserves_source_severity_and_provenance(occurred_at: datetime) -> None:
    alert = make_alert(occurred_at)

    assert alert.source_severity is Severity.MEDIUM
    assert alert.original_payload.reference_id == "payload-001"
    assert alert.contains_entity(UserEntityReference(identifier="user-001"))
    assert not alert.contains_entity(UserEntityReference(identifier="user-002"))


def test_alert_normalizes_aware_timestamps_to_utc() -> None:
    central = timezone(timedelta(hours=-6))
    occurred = datetime(2026, 1, 15, 6, 0, tzinfo=central)

    alert = make_alert(occurred)

    assert alert.occurred_at == datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    assert alert.occurred_at.tzinfo is UTC


@pytest.mark.parametrize("field", ["occurred_at", "detected_at"])
def test_alert_rejects_naive_timestamps(field: str, occurred_at: datetime) -> None:
    replacement = {field: datetime(2026, 1, 15, 12, 0)}
    with pytest.raises(ValidationError, match="timezone-aware"):
        make_alert(**({"occurred_at": occurred_at} | replacement))


def test_alert_rejects_detection_before_occurrence(occurred_at: datetime) -> None:
    with pytest.raises(ValidationError, match="detected_at"):
        make_alert(occurred_at, detected_at=occurred_at - timedelta(seconds=1))


def test_alert_rejects_duplicate_entities(occurred_at: datetime) -> None:
    entity = UserEntityReference(identifier="user-001")
    with pytest.raises(ValidationError, match="entities must be unique"):
        make_alert(occurred_at, entities=(entity, entity))


@pytest.mark.parametrize(
    "payload",
    [
        {"entity_type": "USER", "identifier": ""},
        {"entity_type": "DEVICE", "identifier": "contains spaces"},
        {"entity_type": "IP_ADDRESS", "identifier": "999.0.2.1"},
        {"entity_type": "TENANT", "identifier": "tenant-001"},
    ],
)
def test_malformed_entity_references_are_rejected(payload: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(EntityReference).validate_python(payload)


def test_ipv6_entity_is_normalized_and_round_trips() -> None:
    entity = IpAddressEntityReference(identifier="2001:0db8:0000:0000:0000:0000:0000:0001")
    adapter: TypeAdapter[EntityReference] = TypeAdapter(EntityReference)

    restored = adapter.validate_json(adapter.dump_json(entity))

    assert restored.entity_type is EntityType.IP_ADDRESS
    assert str(restored.identifier) == "2001:db8::1"


def test_alert_rejects_extra_provider_fields(occurred_at: datetime) -> None:
    with pytest.raises(ValidationError, match="provider_specific_command"):
        make_alert(occurred_at, provider_specific_command="disable-user")
