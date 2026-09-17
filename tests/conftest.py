"""Repository-wide test fixtures."""

from pathlib import Path

import pytest

from security_triage_agent.adapters.tools.fixture_models import (
    FixtureDataset,
    load_fixture_dataset,
)


@pytest.fixture(scope="session")
def fixture_root() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "v1"


@pytest.fixture(scope="session")
def fixture_dataset(fixture_root: Path) -> FixtureDataset:
    return load_fixture_dataset(fixture_root)
