"""Small FastAPI adapter and read-only server-rendered analyst interface."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from security_triage_agent.adapters.api.csrf import CsrfProtector
from security_triage_agent.application.action_catalog import ActionCatalog
from security_triage_agent.application.alert_service import (
    AlertConflictError,
    AlertIngestionService,
)
from security_triage_agent.application.approval_service import (
    ApprovalService,
    WorkflowError,
    WorkflowErrorCode,
)
from security_triage_agent.application.orchestrator import TriageOrchestrator
from security_triage_agent.application.ports.auth import (
    AuthorizationService,
    Principal,
    PrincipalProvider,
)
from security_triage_agent.application.ports.reasoner import Clock, IdentifierGenerator
from security_triage_agent.application.ports.repositories import UnitOfWork
from security_triage_agent.domain.alerts import SecurityAlert


class ErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str
    message: str


class TriageRequest(BaseModel):
    """Deliberately empty: callers cannot inject reasoner or policy controls."""

    model_config = ConfigDict(extra="forbid")


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    reason: str = Field(min_length=1, max_length=2_000)


class ExecuteRequest(BaseModel):
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
    approval_service: ApprovalService
    clock: Clock
    max_request_bytes: int = 65_536


def create_app(dependencies: AppDependencies) -> FastAPI:
    app = FastAPI(title="Security Triage Agent", version="0.1.0")
    templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
    app.state.dependencies = dependencies
    csrf = CsrfProtector()

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

    @app.exception_handler(WorkflowError)
    async def workflow_error(_request: Request, error: WorkflowError) -> JSONResponse:
        status_code = 404 if error.code is WorkflowErrorCode.ACTION_NOT_FOUND else 409
        return JSONResponse(
            status_code=status_code,
            content=ErrorResponse(
                code=error.code.value, message="The action workflow request was not permitted."
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

    def reviewer(identity: Annotated[Principal, Depends(principal)]) -> Principal:
        if not dependencies.authorization.may_review(identity):
            raise HTTPException(status_code=403, detail="Reviewer authority required")
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

    def action_payload(action_id: str) -> dict[str, Any]:
        with dependencies.uow_factory() as uow:
            persisted = uow.actions.get_persisted(action_id)
            approval = uow.approvals.get_for_action(action_id)
            execution = uow.action_executions.get_for_action(action_id)
            audit = uow.audit.list_for_target("recommended_action", action_id)
        if persisted is None:
            raise HTTPException(status_code=404, detail="Action not found")
        definition = dependencies.action_catalog.lookup(persisted.action.catalog_action_id)
        return {
            "action": persisted.action.model_dump(mode="json"),
            "action_digest": persisted.action.digest,
            "policy_version": persisted.policy_version,
            "risk": definition.risk.value if definition else "UNKNOWN",
            "approval_required": definition.approval_required if definition else False,
            "execution_support": definition.execution_support.value if definition else "UNKNOWN",
            "approval": approval.model_dump(mode="json") if approval else None,
            "approval_state": (
                "EXPIRED"
                if approval
                and approval.expires_at
                and approval.expires_at <= dependencies.clock.now()
                else approval.decision.value
                if approval
                else "PENDING"
            ),
            "execution": execution.model_dump(mode="json") if execution else None,
            "audit": [item.model_dump(mode="json") for item in audit],
        }

    @app.get("/api/actions/{action_id}")
    def get_action(
        action_id: str, _identity: Annotated[Principal, Depends(viewer)]
    ) -> dict[str, Any]:
        return action_payload(action_id)

    @app.post("/api/actions/{action_id}/approve")
    def approve_action(
        action_id: str,
        body: DecisionRequest,
        identity: Annotated[Principal, Depends(reviewer)],
    ) -> dict[str, Any]:
        approval = dependencies.approval_service.approve(
            action_id, identity.principal_id, body.reason
        )
        return {"approval": approval.model_dump(mode="json")}

    @app.post("/api/actions/{action_id}/reject")
    def reject_action(
        action_id: str,
        body: DecisionRequest,
        identity: Annotated[Principal, Depends(reviewer)],
    ) -> dict[str, Any]:
        approval = dependencies.approval_service.reject(
            action_id, identity.principal_id, body.reason
        )
        return {"approval": approval.model_dump(mode="json")}

    @app.post("/api/actions/{action_id}/execute")
    def execute_action(
        action_id: str,
        _body: ExecuteRequest,
        identity: Annotated[Principal, Depends(reviewer)],
    ) -> dict[str, Any]:
        outcome = dependencies.approval_service.execute(action_id, identity.principal_id)
        return {
            "durable": outcome.durable,
            "execution": outcome.record.model_dump(mode="json"),
        }

    @app.get("/", response_class=HTMLResponse)
    def alert_list(
        request: Request, identity: Annotated[Principal, Depends(viewer)]
    ) -> HTMLResponse:
        with dependencies.uow_factory() as uow:
            alerts = uow.alerts.list_recent()
        session_id, token, created = csrf.issue(request.cookies.get(csrf.cookie_name))
        response = templates.TemplateResponse(
            request,
            "alerts.html",
            {"alerts": alerts, "principal": identity, "csrf_token": token},
        )
        if created:
            response.set_cookie(csrf.cookie_name, session_id, httponly=True, samesite="strict")
        return response

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
        session_id, token, created = csrf.issue(request.cookies.get(csrf.cookie_name))
        response = templates.TemplateResponse(
            request,
            "alert_detail.html",
            {
                "alert": alert,
                "executions": executions,
                "principal": identity,
                "csrf_token": token,
            },
        )
        if created:
            response.set_cookie(csrf.cookie_name, session_id, httponly=True, samesite="strict")
        return response

    @app.get("/executions/{execution_id}", response_class=HTMLResponse)
    def execution_detail(
        request: Request,
        execution_id: str,
        identity: Annotated[Principal, Depends(viewer)],
    ) -> HTMLResponse:
        payload = execution_payload(execution_id)
        session_id, token, created = csrf.issue(request.cookies.get(csrf.cookie_name))
        response = templates.TemplateResponse(
            request,
            "execution_detail.html",
            {
                **payload,
                "principal": identity,
                "reviewer_authorized": dependencies.authorization.may_review(identity),
                "csrf_token": token,
            },
        )
        if created:
            response.set_cookie(csrf.cookie_name, session_id, httponly=True, samesite="strict")
        return response

    @app.get("/actions/{action_id}", response_class=HTMLResponse)
    def action_detail(
        request: Request,
        action_id: str,
        identity: Annotated[Principal, Depends(viewer)],
    ) -> HTMLResponse:
        payload = action_payload(action_id)
        session_id, token, created = csrf.issue(request.cookies.get(csrf.cookie_name))
        response = templates.TemplateResponse(
            request,
            "action_detail.html",
            {
                **payload,
                "principal": identity,
                "reviewer_authorized": dependencies.authorization.may_review(identity),
                "csrf_token": token,
            },
        )
        if created:
            response.set_cookie(csrf.cookie_name, session_id, httponly=True, samesite="strict")
        return response

    async def browser_form(request: Request) -> dict[str, str]:
        if request.headers.get("content-type", "").split(";", 1)[0] != (
            "application/x-www-form-urlencoded"
        ):
            raise HTTPException(status_code=400, detail="Invalid form")
        values = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
        return {key: items[-1] for key, items in values.items() if items}

    def verify_csrf(request: Request, form: dict[str, str]) -> None:
        if not csrf.validate(request.cookies.get(csrf.cookie_name), form.get("csrf_token")):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")

    @app.post("/actions/{action_id}/approve")
    async def browser_approve(
        request: Request,
        action_id: str,
        identity: Annotated[Principal, Depends(reviewer)],
    ) -> RedirectResponse:
        form = await browser_form(request)
        verify_csrf(request, form)
        dependencies.approval_service.approve(
            action_id, identity.principal_id, form.get("reason", "No reason supplied.")
        )
        return RedirectResponse(f"/actions/{action_id}", status_code=303)

    @app.post("/actions/{action_id}/reject")
    async def browser_reject(
        request: Request,
        action_id: str,
        identity: Annotated[Principal, Depends(reviewer)],
    ) -> RedirectResponse:
        form = await browser_form(request)
        verify_csrf(request, form)
        dependencies.approval_service.reject(
            action_id, identity.principal_id, form.get("reason", "No reason supplied.")
        )
        return RedirectResponse(f"/actions/{action_id}", status_code=303)

    @app.post("/actions/{action_id}/execute")
    async def browser_execute(
        request: Request,
        action_id: str,
        identity: Annotated[Principal, Depends(reviewer)],
    ) -> RedirectResponse:
        form = await browser_form(request)
        verify_csrf(request, form)
        dependencies.approval_service.execute(action_id, identity.principal_id)
        return RedirectResponse(f"/actions/{action_id}", status_code=303)

    return app
