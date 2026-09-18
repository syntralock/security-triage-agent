"""Trusted composition root for the local synthetic application."""

from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI
from sqlalchemy.orm import Session, sessionmaker

from security_triage_agent import __version__
from security_triage_agent.adapters.actions import SimulatedActionExecutor
from security_triage_agent.adapters.api.app import AppDependencies, create_app
from security_triage_agent.adapters.persistence.uow import SqlAlchemyUnitOfWork, create_engine
from security_triage_agent.adapters.reasoners.demo import DemoReasoner
from security_triage_agent.adapters.runtime import (
    DevelopmentPrincipalProvider,
    SystemClock,
    UuidIdentifierGenerator,
)
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
from security_triage_agent.application.alert_service import AlertIngestionService
from security_triage_agent.application.approval_service import ApprovalService
from security_triage_agent.application.orchestration_contracts import OrchestrationLimits
from security_triage_agent.application.orchestrator import TriageOrchestrator
from security_triage_agent.application.policy import POLICY_VERSION, DeterministicPolicy
from security_triage_agent.application.ports.auth import AuthorizationService
from security_triage_agent.application.tool_gateway import GatewayLimits, ToolGateway
from security_triage_agent.application.tool_registry import ToolRegistry
from security_triage_agent.config import Environment, Settings, get_settings
from security_triage_agent.evaluation.loader import load_suite
from security_triage_agent.evaluation.runner import EvaluationRunner


def build_dependencies(settings: Settings) -> AppDependencies:
    """Assemble only trusted, configuration-selected implementations."""

    if settings.environment is Environment.PRODUCTION:
        raise RuntimeError("development principal cannot be used in production")
    engine = create_engine(settings.database_url)
    sessions: sessionmaker[Session] = sessionmaker(engine, expire_on_commit=False)

    def uow_factory() -> SqlAlchemyUnitOfWork:
        return SqlAlchemyUnitOfWork(sessions)

    dataset = load_fixture_dataset(Path(settings.fixture_path))
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
    clock = SystemClock()
    identifiers = UuidIdentifierGenerator()
    catalog = initial_action_catalog()
    gateway_limits = GatewayLimits(total_calls=8, per_tool_calls=2)
    orchestrator = TriageOrchestrator(
        reasoner=DemoReasoner(),
        gateway=ToolGateway(
            registry, now=clock.now, monotonic=lambda: clock.monotonic_ms() * 1_000_000
        ),
        policy=DeterministicPolicy(catalog),
        uow_factory=uow_factory,
        clock=clock,
        identifiers=identifiers,
        orchestration_limits=OrchestrationLimits(),
        gateway_limits=gateway_limits,
    )
    authorization = AuthorizationService()
    approval_service = ApprovalService(
        uow_factory=uow_factory,
        catalog=catalog,
        executor=SimulatedActionExecutor(),
        authorization=authorization,
        clock=clock,
        identifiers=identifiers,
        approval_lifetime=timedelta(seconds=settings.approval_lifetime_seconds),
    )
    return AppDependencies(
        uow_factory=uow_factory,
        ingestion=AlertIngestionService(uow_factory, clock, identifiers),
        orchestrator=orchestrator,
        principal_provider=DevelopmentPrincipalProvider(),
        authorization=authorization,
        identifiers=identifiers,
        action_catalog=catalog,
        approval_service=approval_service,
        clock=clock,
        max_request_bytes=settings.max_request_bytes,
    )


def create_default_app() -> FastAPI:
    """Uvicorn factory. Migrations must already be applied."""

    return create_app(build_dependencies(get_settings()))


def build_evaluation_runner(settings: Settings) -> EvaluationRunner:
    """Build the offline evaluator from the same trusted application composition."""

    dependencies = build_dependencies(settings)
    dataset = load_fixture_dataset(Path(settings.fixture_path))
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
        Path(settings.evaluation_path),
        fixtures=dataset,
        registry=registry,
        catalog=dependencies.action_catalog,
    )
    return EvaluationRunner(
        suite=suite,
        alerts=dataset.alerts,
        orchestrator=dependencies.orchestrator,
        uow_factory=dependencies.uow_factory,
        clock=dependencies.clock,
        identifiers=dependencies.identifiers,
        reasoner_label="deterministic-demo-v1",
        policy_version=POLICY_VERSION,
        application_version=__version__,
    )
