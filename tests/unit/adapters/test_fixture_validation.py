"""Fixture schema, safety, and referential-integrity validation tests."""

import json
import shutil
from dataclasses import replace
from ipaddress import ip_address
from pathlib import Path

import pytest
from scripts.verify_fixtures import main as verify_main

from security_triage_agent.adapters.tools.fixture_models import (
    FixtureDataset,
    FixtureValidationError,
    RelatedAlertRecord,
    load_fixture_dataset,
    validate_fixture_dataset,
)
from security_triage_agent.application.evidence_tools import UserRisk
from security_triage_agent.domain.entities import UserEntityReference


def test_v1_fixture_dataset_loads_with_expected_records(fixture_root: Path) -> None:
    dataset = load_fixture_dataset(fixture_root)

    assert dataset.manifest.fixture_version == "v1"
    assert len(dataset.identities) == 2
    assert len(dataset.sign_ins) == 4
    assert len(dataset.devices) == 2
    assert len(dataset.ip_reputations) == 4
    assert len(dataset.mfa_events) == 3
    assert len(dataset.alerts) == 3


def test_fixture_validator_rejects_duplicate_identifiers(
    fixture_dataset: FixtureDataset,
) -> None:
    dataset = fixture_dataset
    invalid = replace(dataset, identities=(*dataset.identities, dataset.identities[0]))

    with pytest.raises(FixtureValidationError, match="duplicate identity"):
        validate_fixture_dataset(invalid)


def test_fixture_validator_rejects_unknown_signin_device(
    fixture_dataset: FixtureDataset,
) -> None:
    dataset = fixture_dataset
    invalid_signin = dataset.sign_ins[0].model_copy(update={"device_id": "device-missing"})
    invalid = replace(dataset, sign_ins=(invalid_signin, *dataset.sign_ins[1:]))

    with pytest.raises(FixtureValidationError, match="unknown sign-in device"):
        validate_fixture_dataset(invalid)


def test_fixture_validator_rejects_unknown_related_alert(
    fixture_dataset: FixtureDataset,
) -> None:
    dataset = fixture_dataset
    invalid_mapping = RelatedAlertRecord(user_id="user-alex", alert_ids=("alert-missing",))
    invalid = replace(dataset, related_alerts=(invalid_mapping, *dataset.related_alerts[1:]))

    with pytest.raises(FixtureValidationError, match="unknown related alert"):
        validate_fixture_dataset(invalid)


def test_fixture_loader_rejects_unsupported_version(fixture_root: Path, tmp_path: Path) -> None:
    copied = tmp_path / "fixtures"
    shutil.copytree(fixture_root, copied)
    manifest_path = copied / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["fixture_version"] = "v999"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(FixtureValidationError, match="unsupported fixture version"):
        load_fixture_dataset(copied)


def test_fixture_validator_rejects_unsupported_schema(
    fixture_dataset: FixtureDataset,
) -> None:
    manifest = fixture_dataset.manifest.model_copy(update={"schema_version": "999"})

    with pytest.raises(FixtureValidationError, match="unsupported schema version"):
        validate_fixture_dataset(replace(fixture_dataset, manifest=manifest))


def test_fixture_validator_rejects_unknown_risk_identity(
    fixture_dataset: FixtureDataset,
) -> None:
    risk = UserRisk.model_validate(
        fixture_dataset.user_risks[0].model_dump() | {"user_id": "user-missing"}
    )

    with pytest.raises(FixtureValidationError, match="unknown user risk identity"):
        validate_fixture_dataset(replace(fixture_dataset, user_risks=(risk,)))


def test_fixture_validator_requires_bidirectional_identity_ownership(
    fixture_dataset: FixtureDataset,
) -> None:
    device = fixture_dataset.devices[0].model_copy(update={"owner_user_ids": ()})
    invalid = replace(fixture_dataset, devices=(device, *fixture_dataset.devices[1:]))

    with pytest.raises(FixtureValidationError, match="ownership is not bidirectional"):
        validate_fixture_dataset(invalid)


def test_fixture_validator_requires_bidirectional_device_ownership(
    fixture_dataset: FixtureDataset,
) -> None:
    identity = fixture_dataset.identities[0].model_copy(update={"device_ids": ()})
    invalid = replace(fixture_dataset, identities=(identity, *fixture_dataset.identities[1:]))

    with pytest.raises(FixtureValidationError, match="ownership is not bidirectional"):
        validate_fixture_dataset(invalid)


def test_fixture_validator_rejects_signin_on_another_users_device(
    fixture_dataset: FixtureDataset,
) -> None:
    sign_in = fixture_dataset.sign_ins[0].model_copy(update={"user_id": "user-riley"})
    invalid = replace(fixture_dataset, sign_ins=(sign_in, *fixture_dataset.sign_ins[1:]))

    with pytest.raises(FixtureValidationError, match="not owned by the referenced user"):
        validate_fixture_dataset(invalid)


def test_fixture_validator_rejects_mfa_user_mismatch(
    fixture_dataset: FixtureDataset,
) -> None:
    event = fixture_dataset.mfa_events[0].model_copy(update={"user_id": "user-riley"})
    invalid = replace(fixture_dataset, mfa_events=(event, *fixture_dataset.mfa_events[1:]))

    with pytest.raises(FixtureValidationError, match="reference different users"):
        validate_fixture_dataset(invalid)


def test_fixture_validator_rejects_alert_mapped_to_wrong_user(
    fixture_dataset: FixtureDataset,
) -> None:
    mapping = RelatedAlertRecord(user_id="user-alex", alert_ids=("alert-riley-risk",))
    invalid = replace(
        fixture_dataset, related_alerts=(mapping, *fixture_dataset.related_alerts[1:])
    )

    with pytest.raises(FixtureValidationError, match="does not reference the mapped user"):
        validate_fixture_dataset(invalid)


def test_fixture_validator_rejects_unknown_alert_entity(
    fixture_dataset: FixtureDataset,
) -> None:
    alert = fixture_dataset.alerts[0].model_copy(
        update={
            "alert_id": "alert-unmapped-invalid",
            "entities": (UserEntityReference(identifier="user-missing"),),
        }
    )
    invalid = replace(fixture_dataset, alerts=(*fixture_dataset.alerts, alert))

    with pytest.raises(FixtureValidationError, match="unknown alert identity"):
        validate_fixture_dataset(invalid)


def test_fixture_validator_rejects_duplicate_nested_references(
    fixture_dataset: FixtureDataset,
) -> None:
    identity = fixture_dataset.identities[0].model_copy(
        update={"device_ids": ("device-alex-laptop", "device-alex-laptop")}
    )
    invalid = replace(fixture_dataset, identities=(identity, *fixture_dataset.identities[1:]))

    with pytest.raises(FixtureValidationError, match="duplicate value"):
        validate_fixture_dataset(invalid)


@pytest.mark.parametrize(
    ("filename", "field", "value"),
    [
        ("signins.json", "ip_address", "not-an-ip"),
        ("signins.json", "occurred_at", "not-a-timestamp"),
        ("identities.json", "unexpected", "forbidden"),
    ],
)
def test_fixture_loader_rejects_malformed_records(
    fixture_root: Path,
    tmp_path: Path,
    filename: str,
    field: str,
    value: str,
) -> None:
    copied = tmp_path / "fixtures"
    shutil.copytree(fixture_root, copied)
    path = copied / filename
    records = json.loads(path.read_text(encoding="utf-8"))
    records[0][field] = value
    path.write_text(json.dumps(records), encoding="utf-8")

    with pytest.raises(FixtureValidationError, match="fixture loading failed"):
        load_fixture_dataset(copied)


def test_synthetic_data_uses_reserved_addresses_and_test_domains(
    fixture_dataset: FixtureDataset,
) -> None:
    dataset = fixture_dataset

    assert all(not ip_address(str(item.ip_address)).is_global for item in dataset.ip_reputations)
    assert all(item.principal_name.endswith(".example.test") for item in dataset.identities)
    serialized = " ".join(
        item.model_dump_json()
        for collection in (
            dataset.identities,
            dataset.sign_ins,
            dataset.devices,
            dataset.alerts,
        )
        for item in collection
    ).lower()
    assert "contoso" not in serialized
    assert "microsoft.com" not in serialized


def test_fixture_verification_command_success_and_failure(
    fixture_root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert verify_main([str(fixture_root)]) == 0
    assert "fixture validation passed" in capsys.readouterr().out

    assert verify_main([str(tmp_path / "missing")]) == 1
    assert "fixture validation failed" in capsys.readouterr().out
