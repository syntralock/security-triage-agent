"""Validate a versioned evaluation suite without executing triage."""

import argparse
from collections.abc import Sequence
from pathlib import Path

from security_triage_agent.adapters.tools import (
    FixtureDeviceContextTool,
    FixtureIdentityContextTool,
    FixtureIpReputationTool,
    FixtureMfaEventsTool,
    FixtureRecentSignInsTool,
    FixtureRelatedAlertsTool,
    FixtureUserRiskTool,
)
from security_triage_agent.adapters.tools.fixture_models import load_fixture_dataset
from security_triage_agent.application.action_catalog import initial_action_catalog
from security_triage_agent.application.tool_registry import ToolRegistry
from security_triage_agent.evaluation.loader import load_suite


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="validate synthetic evaluation data")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("fixtures", type=Path)
    args = parser.parse_args(argv)
    dataset = load_fixture_dataset(args.fixtures)
    registry = ToolRegistry(
        (
            FixtureRecentSignInsTool(dataset),
            FixtureUserRiskTool(dataset),
            FixtureDeviceContextTool(dataset),
            FixtureIpReputationTool(dataset),
            FixtureMfaEventsTool(dataset),
            FixtureRelatedAlertsTool(dataset),
            FixtureIdentityContextTool(dataset),
        )
    )
    suite = load_suite(
        args.manifest,
        fixtures=dataset,
        registry=registry,
        catalog=initial_action_catalog(),
    )
    print(
        f"evaluation validation passed: suite={suite.suite_version} "
        f"scenarios={len(suite.scenarios)} fixture={suite.fixture_version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
