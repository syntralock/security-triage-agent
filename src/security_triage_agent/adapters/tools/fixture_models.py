"""Versioned fixture schemas, loading, and referential-integrity validation."""

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field, TypeAdapter, ValidationError

from security_triage_agent.application.evidence_tools import (
    DeviceContext,
    IdentityContext,
    IpReputation,
    MfaEvent,
    SignInEvent,
    UserRisk,
)
from security_triage_agent.domain._base import DomainModel, Identifier, UtcDatetime, Version
from security_triage_agent.domain.alerts import SecurityAlert
from security_triage_agent.domain.entities import (
    DeviceEntityReference,
    IpAddressEntityReference,
    UserEntityReference,
)

SUPPORTED_FIXTURE_VERSION = "v1"
SUPPORTED_SCHEMA_VERSION = "1.0"


class FixtureValidationError(ValueError):
    """Raised when fixture structure or cross-record references are invalid."""


class FixtureManifest(DomainModel):
    fixture_version: Version
    schema_version: Version
    reference_time: UtcDatetime
    recent_signin_window_hours: int = Field(gt=0, le=24 * 30)


class RelatedAlertRecord(DomainModel):
    user_id: Identifier
    alert_ids: tuple[Identifier, ...]


@dataclass(frozen=True, slots=True)
class FixtureDataset:
    """Validated immutable snapshot used by all fixture-backed adapters."""

    manifest: FixtureManifest
    identities: tuple[IdentityContext, ...]
    user_risks: tuple[UserRisk, ...]
    devices: tuple[DeviceContext, ...]
    sign_ins: tuple[SignInEvent, ...]
    ip_reputations: tuple[IpReputation, ...]
    mfa_events: tuple[MfaEvent, ...]
    related_alerts: tuple[RelatedAlertRecord, ...]
    alerts: tuple[SecurityAlert, ...]


def load_fixture_dataset(root: Path) -> FixtureDataset:
    """Load and fully validate one explicit fixture-version directory."""

    try:
        dataset = FixtureDataset(
            manifest=_read_model(root / "manifest.json", FixtureManifest),
            identities=_read_records(root / "identities.json", IdentityContext),
            user_risks=_read_records(root / "user_risk.json", UserRisk),
            devices=_read_records(root / "devices.json", DeviceContext),
            sign_ins=_read_records(root / "signins.json", SignInEvent),
            ip_reputations=_read_records(root / "ip_reputation.json", IpReputation),
            mfa_events=_read_records(root / "mfa_events.json", MfaEvent),
            related_alerts=_read_records(root / "related_alerts.json", RelatedAlertRecord),
            alerts=_read_records(root / "alerts" / "alerts.json", SecurityAlert),
        )
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise FixtureValidationError(f"fixture loading failed: {exc}") from exc
    validate_fixture_dataset(dataset)
    return dataset


def validate_fixture_dataset(dataset: FixtureDataset) -> None:
    """Enforce supported versions, uniqueness, and all cross-record references."""

    manifest = dataset.manifest
    if manifest.fixture_version != SUPPORTED_FIXTURE_VERSION:
        raise FixtureValidationError(f"unsupported fixture version: {manifest.fixture_version}")
    if manifest.schema_version != SUPPORTED_SCHEMA_VERSION:
        raise FixtureValidationError(f"unsupported schema version: {manifest.schema_version}")

    identities = _unique_index(dataset.identities, "user_id", "identity")
    risks = _unique_index(dataset.user_risks, "user_id", "user risk")
    devices = _unique_index(dataset.devices, "device_id", "device")
    sign_ins = _unique_index(dataset.sign_ins, "sign_in_id", "sign-in")
    ip_records = _unique_index(dataset.ip_reputations, "ip_address", "IP reputation")
    _unique_index(dataset.mfa_events, "mfa_event_id", "MFA event")
    related = _unique_index(dataset.related_alerts, "user_id", "related-alert mapping")
    alerts = _unique_index(dataset.alerts, "alert_id", "alert")

    for identity in identities.values():
        _require_unique_values(identity.device_ids, f"identity {identity.user_id} device_ids")
        for device_id in identity.device_ids:
            device = _require_reference(devices, device_id, "identity device")
            if identity.user_id not in device.owner_user_ids:
                raise FixtureValidationError("identity/device ownership is not bidirectional")

    for device in devices.values():
        _require_unique_values(device.owner_user_ids, f"device {device.device_id} owner_user_ids")
        for user_id in device.owner_user_ids:
            identity = _require_reference(identities, user_id, "device owner")
            if device.device_id not in identity.device_ids:
                raise FixtureValidationError("device/identity ownership is not bidirectional")

    for risk in risks.values():
        _require_reference(identities, risk.user_id, "user risk identity")

    for sign_in in sign_ins.values():
        _require_reference(identities, sign_in.user_id, "sign-in identity")
        _require_reference(devices, sign_in.device_id, "sign-in device")
        _require_reference(ip_records, str(sign_in.ip_address), "sign-in IP reputation")
        if sign_in.user_id not in devices[sign_in.device_id].owner_user_ids:
            raise FixtureValidationError("sign-in device is not owned by the referenced user")

    for event in dataset.mfa_events:
        _require_reference(identities, event.user_id, "MFA identity")
        sign_in = _require_reference(sign_ins, event.source_sign_in_id, "MFA sign-in")
        if sign_in.user_id != event.user_id:
            raise FixtureValidationError("MFA event and sign-in reference different users")

    for mapping in related.values():
        _require_reference(identities, mapping.user_id, "related-alert identity")
        _require_unique_values(mapping.alert_ids, f"related alerts for {mapping.user_id}")
        for alert_id in mapping.alert_ids:
            alert = _require_reference(alerts, alert_id, "related alert")
            if not any(
                isinstance(entity, UserEntityReference) and entity.identifier == mapping.user_id
                for entity in alert.entities
            ):
                raise FixtureValidationError("related alert does not reference the mapped user")

    for alert in alerts.values():
        for entity in alert.entities:
            if isinstance(entity, UserEntityReference):
                _require_reference(identities, entity.identifier, "alert identity")
            elif isinstance(entity, DeviceEntityReference):
                _require_reference(devices, entity.identifier, "alert device")
            elif isinstance(entity, IpAddressEntityReference):
                _require_reference(ip_records, str(entity.identifier), "alert IP reputation")


def _read_model[ModelT: BaseModel](path: Path, model: type[ModelT]) -> ModelT:
    return model.model_validate_json(path.read_text(encoding="utf-8"))


def _read_records[ModelT: BaseModel](path: Path, model: type[ModelT]) -> tuple[ModelT, ...]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return TypeAdapter(tuple[model, ...]).validate_python(data)  # type: ignore[valid-type]


def _unique_index[ModelT: BaseModel](
    records: tuple[ModelT, ...], attribute: str, label: str
) -> dict[str, ModelT]:
    return _make_unique_index(
        ((str(getattr(record, attribute)), record) for record in records), label
    )


def _make_unique_index[ModelT: BaseModel](
    items: Iterable[tuple[str, ModelT]], label: str
) -> dict[str, ModelT]:
    result: dict[str, ModelT] = {}
    for identifier, record in items:
        if identifier in result:
            raise FixtureValidationError(f"duplicate {label} identifier: {identifier}")
        result[identifier] = record
    return result


def _require_reference[ModelT: BaseModel](
    index: dict[str, ModelT], identifier: str, label: str
) -> ModelT:
    try:
        return index[identifier]
    except KeyError as exc:
        raise FixtureValidationError(f"unknown {label} reference: {identifier}") from exc


def _require_unique_values(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise FixtureValidationError(f"duplicate value in {label}")
