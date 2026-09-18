"""Small FastAPI adapter and read-only server-rendered analyst interface."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict

from security_triage_agent.application.action_catalog import ActionCatalog
from security_triage_agent.application.alert_service import (
    AlertConflictError,
    AlertIngestionService,
)
from security_triage_agent.application.orchestrator import TriageOrchestrator
from security_triage_agent.application.ports.auth import (
    AuthorizationService,
    Principal,
    PrincipalProvider,
)
from security_triage_agent.application.ports.reasoner import IdentifierGenerator
from security_triage_agent.application.ports.repositories import UnitOfWork
from security_triage_agent.domain.alerts import SecurityAlert


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    message: str


class TriageRequest(BaseModel):
    """Deliberately empty: callers cannot inject reasoner or policy controls."""

    model_config = ConfigDict(extra="forbid")


@dataclass(frozen=True, slots=True)
class AppDependencies:
    uow_factory: Callable[[], UnitOfWork]
    ingestion: AlertIngestionService
    orchestrator: TriageOrchestrator
    principal_provider: PrincipalProvider
    authorization: AuthorizationService
    identifiers: IdentifierGenerator
    action_catalog: ActionCatalog
    max_request_bytes: int = 65_536


def create_app(dependencies: AppDependencies) -> FastAPI:
    app = FastAPI(title="Security Triage Agent", version="0.1.0")
    templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
    app.state.dependencies = dependencies

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _error: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            content=ErrorResponse(
                code="VALIDATION_ERROR", message="Request validation failed."
            ).model_dump(),
        )

    @app.exception_handler(HTTPException)
    async def http_error(_request: Request, error: HTTPException) -> JSONResponse:
        messages = {
            401: "Authentication required.",
            403: "Access denied.",
            404: "Resource not found.",
            409: "Resource conflict.",
            503: "Service unavailable.",
        }
        return JSONResponse(
            status_code=error.status_code,
            content=ErrorResponse(
                code=f"HTTP_{error.status_code}",
                message=messages.get(error.status_code, "The request could not be completed."),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def internal_error(_request: Request, _error: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                code="INTERNAL_ERROR", message="The request could not be completed."
            ).model_dump(),
        )

    def principal() -> Principal:
        value = dependencies.principal_provider.current_principal()
        if value is None:
            raise HTTPException(status_code=401, detail="Authentication required")
        return value

    def viewer(identity: Annotated[Principal, Depends(principal)]) -> Principal:
        if not dependencies.authorization.may_view(identity):
            raise HTTPException(status_code=403, detail="Access denied")
        return identity

    def analyst(identity: Annotated[Principal, Depends(principal)]) -> Principal:
        if not dependencies.authorization.may_ingest_or_triage(identity):
            raise HTTPException(status_code=403, detail="Access denied")
        return identity

    @app.middleware("http")
    async def request_size_limit(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        length = request.headers.get("content-length")
        try:
            exceeds_limit = length is not None and int(length) > dependencies.max_request_bytes
        except ValueError:
            return JSONResponse(
                status_code=400,
                content=ErrorResponse(
                    code="INVALID_CONTENT_LENGTH", message="Invalid request metadata."
                ).model_dump(),
            )
        if exceeds_limit:
            return JSONResponse(
                status_code=413,
                content=ErrorResponse(
                    code="REQUEST_TOO_LARGE", message="Request body exceeds the size limit."
                ).model_dump(),
            )
        if request.method in {"POST", "PUT", "PATCH"}:
            body = await request.body()
            if len(body) > dependencies.max_request_bytes:
                return JSONResponse(
                    status_code=413,
                    content=ErrorResponse(
                        code="REQUEST_TOO_LARGE",
                        message="Request body exceeds the size limit.",
                    ).model_dump(),
                )
        return await call_next(request)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/ready")
    def ready() -> dict[str, str]:
        try:
            with dependencies.uow_factory() as uow:
                uow.alerts.list_recent(limit=1)
            return {"status": "ready"}
        except Exception as error:
            raise HTTPException(status_code=503, detail="Persistence unavailable") from error

    @app.post("/api/alerts", response_model=dict[str, Any])
    def ingest_alert(
        alert: SecurityAlert,
        identity: Annotated[Principal, Depends(analyst)],
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1)],
    ) -> JSONResponse:
        try:
            result = dependencies.ingestion.ingest(
                alert, correlation_id=idempotency_key, actor_id=identity.principal_id
            )
        except AlertConflictError as error:
            raise HTTPException(status_code=409, detail="Alert identifier conflict") from error
        return JSONResponse(
            status_code=201 if result.created else 200,
            content={"created": result.created, "alert": result.alert.model_dump(mode="json")},
        )

    @app.get("/api/alerts")
    def list_alerts(_identity: Annotated[Principal, Depends(viewer)]) -> dict[str, Any]:
        with dependencies.uow_factory() as uow:
            alerts = uow.alerts.list_recent()
        return {"alerts": [item.model_dump(mode="json") for item in alerts]}

    @app.get("/api/alerts/{alert_id}")
    def get_alert(
        alert_id: str, _identity: Annotated[Principal, Depends(viewer)]
    ) -> dict[str, Any]:
        with dependencies.uow_factory() as uow:
            alert = uow.alerts.get(alert_id)
            executions = uow.executions.list_for_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return {
            "alert": alert.model_dump(mode="json"),
            "executions": [item.model_dump(mode="json") for item in executions],
        }

    @app.post("/api/alerts/{alert_id}/triage")
    def triage_alert(
        alert_id: str,
        _request: TriageRequest,
        _identity: Annotated[Principal, Depends(analyst)],
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1)],
    ) -> dict[str, Any]:
        with dependencies.uow_factory() as uow:
            alert = uow.alerts.get(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        outcome = dependencies.orchestrator.run(
            alert,
            idempotency_key=idempotency_key,
            execution_id=dependencies.identifiers.next_id("execution"),
            correlation_id=dependencies.identifiers.next_id("correlation"),
        )
        if not outcome.durable:
            raise HTTPException(status_code=503, detail="Triage result was not durably persisted")
        return outcome.model_dump(mode="json")

    def execution_payload(execution_id: str) -> dict[str, Any]:
        with dependencies.uow_factory() as uow:
            execution = uow.executions.get(execution_id)
            result = uow.triage_results.get_for_execution(execution_id)
            alert = uow.alerts.get(execution.alert_id) if execution else None
            tools = uow.tool_invocations.list_for_execution(execution_id)
            audit = uow.audit.list_for_target("triage_execution", execution_id)
        if execution is None:
            raise HTTPException(status_code=404, detail="Execution not found")
        actions = []
        if result is not None:
            approval_ids = {item.action_id for item in result.actions_requiring_approval}
            for action in result.recommended_actions:
                definition = dependencies.action_catalog.lookup(action.catalog_action_id)
                actions.append(
                    {
                        **action.model_dump(mode="json"),
                        "approval_required": action.action_id in approval_ids,
                        "risk": definition.risk.value if definition else "UNKNOWN",
                        "execution_support": (
                            definition.execution_support.value if definition else "UNKNOWN"
                        ),
                    }
                )
        policy_event = next(
            (item for item in audit if item.event_type == "triage.policy_enforced"), None
        )
        return {
            "execution": execution.model_dump(mode="json"),
            "result": result.model_dump(mode="json") if result else None,
            "tools": [item.model_dump(mode="json") for item in tools],
            "audit": [item.model_dump(mode="json") for item in audit],
            "actions": actions,
            "policy": policy_event.data if policy_event else None,
            "source_severity": alert.source_severity.value if alert else None,
        }

    @app.get("/api/executions/{execution_id}")
    def get_execution(
        execution_id: str, _identity: Annotated[Principal, Depends(viewer)]
    ) -> dict[str, Any]:
        return execution_payload(execution_id)

    @app.get("/api/executions/{execution_id}/tools")
    def get_tools(
        execution_id: str, _identity: Annotated[Principal, Depends(viewer)]
    ) -> dict[str, Any]:
        payload = execution_payload(execution_id)
        return {"tools": payload["tools"]}

    @app.get("/api/executions/{execution_id}/audit")
    def get_audit(
        execution_id: str, _identity: Annotated[Principal, Depends(viewer)]
    ) -> dict[str, Any]:
        payload = execution_payload(execution_id)
        return {"audit": payload["audit"]}

    @app.get("/", response_class=HTMLResponse)
    def alert_list(
        request: Request, identity: Annotated[Principal, Depends(viewer)]
    ) -> HTMLResponse:
        with dependencies.uow_factory() as uow:
            alerts = uow.alerts.list_recent()
        return templates.TemplateResponse(
            request,
            "alerts.html",
            {"alerts": alerts, "principal": identity},
        )

    @app.get("/alerts/{alert_id}", response_class=HTMLResponse)
    def alert_detail(
        request: Request,
        alert_id: str,
        identity: Annotated[Principal, Depends(viewer)],
    ) -> HTMLResponse:
        with dependencies.uow_factory() as uow:
            alert = uow.alerts.get(alert_id)
            executions = uow.executions.list_for_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return templates.TemplateResponse(
            request,
            "alert_detail.html",
            {"alert": alert, "executions": executions, "principal": identity},
        )

    @app.get("/executions/{execution_id}", response_class=HTMLResponse)
    def execution_detail(
        request: Request,
        execution_id: str,
        identity: Annotated[Principal, Depends(viewer)],
    ) -> HTMLResponse:
        payload = execution_payload(execution_id)
        return templates.TemplateResponse(
            request,
            "execution_detail.html",
            {**payload, "principal": identity},
        )

    return app
