"""Validate one explicit versioned fixture dataset."""

import argparse
from collections.abc import Sequence
from pathlib import Path

from security_triage_agent.adapters.tools.fixture_models import (
    FixtureValidationError,
    load_fixture_dataset,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture_directory", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        dataset = load_fixture_dataset(args.fixture_directory)
    except FixtureValidationError as exc:
        print(f"fixture validation failed: {exc}")
        return 1
    print(
        "fixture validation passed: "
        f"version={dataset.manifest.fixture_version} "
        f"identities={len(dataset.identities)} "
        f"alerts={len(dataset.alerts)}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a script
    raise SystemExit(main())
