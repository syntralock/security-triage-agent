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
from security_triage_agent.adapters.reasoners.openai import OpenAIReasoner
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
from security_triage_agent.config import Environment, ReasonerProvider, Settings, get_settings
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
    reasoner = _build_reasoner(settings)
    orchestrator = TriageOrchestrator(
        reasoner=reasoner,
        gateway=ToolGateway(
            registry, now=clock.now, monotonic=lambda: clock.monotonic_ms() * 1_000_000
        ),
        policy=DeterministicPolicy(catalog, lambda: identifiers.next_id("action")),
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
    if settings.reasoner_provider is ReasonerProvider.OPENAI:
        reasoner_label = f"openai:{settings.openai_model}:{settings.openai_prompt_version}"
        reasoner_implementation = "OpenAIReasoner"
        provider = "openai"
        model = settings.openai_model
        prompt_version: str = settings.openai_prompt_version
    else:
        reasoner_label = "deterministic-demo-v1"
        reasoner_implementation = "DemoReasoner"
        provider = "offline"
        model = "deterministic-demo-v1"
        prompt_version = "demo-v1"
    return EvaluationRunner(
        suite=suite,
        alerts=dataset.alerts,
        orchestrator=dependencies.orchestrator,
        uow_factory=dependencies.uow_factory,
        clock=dependencies.clock,
        identifiers=dependencies.identifiers,
        reasoner_label=reasoner_label,
        reasoner_implementation=reasoner_implementation,
        provider=provider,
        model=model,
        prompt_version=prompt_version,
        policy_version=POLICY_VERSION,
        application_version=__version__,
    )


def _build_reasoner(settings: Settings) -> DemoReasoner | OpenAIReasoner:
    if settings.reasoner_provider is ReasonerProvider.DEMO:
        return DemoReasoner()
    if settings.openai_api_key is None:
        raise RuntimeError("OpenAI reasoner is enabled but OPENAI_API_KEY is not configured")
    return OpenAIReasoner(
        api_key=settings.openai_api_key.get_secret_value(),
        model=settings.openai_model,
        timeout_seconds=settings.openai_request_timeout_seconds,
        max_output_tokens=settings.openai_max_output_tokens,
        prompt_version=settings.openai_prompt_version,
    )
