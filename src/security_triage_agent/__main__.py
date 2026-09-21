"""Foundation command used for installation and container smoke checks."""

import argparse
import logging
from collections.abc import Sequence

from security_triage_agent import __version__
from security_triage_agent.config import get_settings
from security_triage_agent.logging import configure_logging, log_event


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Security Triage Agent foundation command")
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate configuration and package startup, then exit",
    )
    parser.add_argument(
        "--recover-stale",
        action="store_true",
        help="explicitly fail stale RUNNING triage and EXECUTING simulated-action records",
    )
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    settings.validate_runtime_profile()
    configure_logging(settings)
    if args.recover_stale:
        from security_triage_agent.bootstrap import build_dependencies

        dependencies = build_dependencies(settings)
        report = dependencies.recovery_service.recover_all(
            operator_id="system-recovery-operator",
            correlation_id=dependencies.identifiers.next_id("recovery-correlation"),
        )
        log_event(
            logging.getLogger("security_triage_agent"),
            logging.INFO,
            "stale_recovery_completed",
            stale_executions_failed=report.stale_executions_failed,
            stale_actions_failed=report.stale_actions_failed,
        )
        return 0
    log_event(
        logging.getLogger("security_triage_agent"),
        logging.INFO,
        "foundation_ready",
        environment=settings.environment.value,
        service=settings.service_name,
        check=args.check,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by container smoke check
    raise SystemExit(main())
