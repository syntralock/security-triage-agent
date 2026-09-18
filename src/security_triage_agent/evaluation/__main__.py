"""CLI for offline deterministic evaluation."""

import argparse
from collections.abc import Sequence

from security_triage_agent.bootstrap import build_evaluation_runner
from security_triage_agent.config import get_settings
from security_triage_agent.evaluation.reporting import render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run deterministic synthetic evaluations")
    parser.add_argument("--scenario", help="run one stable scenario identifier")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = build_evaluation_runner(get_settings()).run(args.scenario)
    print(render_json(report) if args.json else render_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
