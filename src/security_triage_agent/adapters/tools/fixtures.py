"""Deterministic, read-only evidence tools backed by a validated fixture snapshot."""

from datetime import timedelta
from typing import cast

from pydantic import BaseModel

from security_triage_agent.adapters.tools.fixture_models import FixtureDataset
from security_triage_agent.application.evidence_tools import (
    DeviceContext,
    DeviceRequest,
    IdentityContext,
    IpAddressRequest,
    IpReputation,
    MfaEvents,
    RecentSignIns,
    RelatedAlerts,
    RelatedAlertSummary,
    UserRequest,
    UserRisk,
)
from security_triage_agent.application.ports.tools import (
    DataClassification,
    Found,
    NotFound,
    ToolAccess,
    ToolMetadata,
    ToolOutcome,
    ToolProvenance,
)

TOOL_VERSION = "1.0.0"
DEFAULT_TIMEOUT_MS = 250


class _FixtureTool[RequestT: BaseModel, ResponseT: BaseModel]:
    metadata: ToolMetadata[RequestT, ResponseT]

    def __init__(self, dataset: FixtureDataset) -> None:
        self._dataset = dataset

    @property
    def provenance(self) -> ToolProvenance:
        return ToolProvenance(
            tool_name=self.metadata.name,
            tool_version=self.metadata.version,
            fixture_version=self._dataset.manifest.fixture_version,
        )

    def _found(self, data: ResponseT) -> Found[ResponseT]:
        response_model = self.metadata.response_model
        outcome_model = Found[response_model]  # type: ignore[valid-type]
        return cast(
            Found[ResponseT],
            outcome_model(provenance=self.provenance, data=data),
        )

    def _not_found(self, resource_type: str, identifier: str) -> NotFound:
        return NotFound(
            provenance=self.provenance,
            resource_type=resource_type,
            identifier=identifier,
            message=f"Synthetic {resource_type} not found for {identifier}",
        )


class FixtureRecentSignInsTool(_FixtureTool[UserRequest, RecentSignIns]):
    metadata = ToolMetadata(
        name="get_recent_signins",
        version=TOOL_VERSION,
        access=ToolAccess.READ_ONLY,
        data_classification=DataClassification.SYNTHETIC_DEMO,
        timeout_ms=DEFAULT_TIMEOUT_MS,
        request_model=UserRequest,
        response_model=RecentSignIns,
    )

    def execute(self, request: UserRequest) -> ToolOutcome[RecentSignIns]:
        if not any(item.user_id == request.user_id for item in self._dataset.identities):
            return self._not_found("identity", request.user_id)
        reference = self._dataset.manifest.reference_time
        window_start = reference - timedelta(
            hours=self._dataset.manifest.recent_signin_window_hours
        )
        sign_ins = tuple(
            sorted(
                (
                    item
                    for item in self._dataset.sign_ins
                    if item.user_id == request.user_id
                    and window_start <= item.occurred_at <= reference
                ),
                key=lambda item: (item.occurred_at, item.sign_in_id),
                reverse=True,
            )
        )
        return self._found(
            RecentSignIns(
                user_id=request.user_id,
                reference_time=reference,
                window_started_at=window_start,
                sign_ins=sign_ins,
            )
        )


class FixtureUserRiskTool(_FixtureTool[UserRequest, UserRisk]):
    metadata = ToolMetadata(
        name="get_user_risk",
        version=TOOL_VERSION,
        access=ToolAccess.READ_ONLY,
        data_classification=DataClassification.SYNTHETIC_DEMO,
        timeout_ms=DEFAULT_TIMEOUT_MS,
        request_model=UserRequest,
        response_model=UserRisk,
    )

    def execute(self, request: UserRequest) -> ToolOutcome[UserRisk]:
        risk = next(
            (item for item in self._dataset.user_risks if item.user_id == request.user_id),
            None,
        )
        return self._found(risk) if risk else self._not_found("user-risk", request.user_id)


class FixtureDeviceContextTool(_FixtureTool[DeviceRequest, DeviceContext]):
    metadata = ToolMetadata(
        name="get_device_context",
        version=TOOL_VERSION,
        access=ToolAccess.READ_ONLY,
        data_classification=DataClassification.SYNTHETIC_DEMO,
        timeout_ms=DEFAULT_TIMEOUT_MS,
        request_model=DeviceRequest,
        response_model=DeviceContext,
    )

    def execute(self, request: DeviceRequest) -> ToolOutcome[DeviceContext]:
        device = next(
            (item for item in self._dataset.devices if item.device_id == request.device_id),
            None,
        )
        return self._found(device) if device else self._not_found("device", request.device_id)


class FixtureIpReputationTool(_FixtureTool[IpAddressRequest, IpReputation]):
    metadata = ToolMetadata(
        name="get_ip_reputation",
        version=TOOL_VERSION,
        access=ToolAccess.READ_ONLY,
        data_classification=DataClassification.SYNTHETIC_DEMO,
        timeout_ms=DEFAULT_TIMEOUT_MS,
        request_model=IpAddressRequest,
        response_model=IpReputation,
    )

    def execute(self, request: IpAddressRequest) -> ToolOutcome[IpReputation]:
        normalized = str(request.ip_address)
        reputation = next(
            (item for item in self._dataset.ip_reputations if str(item.ip_address) == normalized),
            None,
        )
        return (
            self._found(reputation) if reputation else self._not_found("ip-reputation", normalized)
        )


class FixtureMfaEventsTool(_FixtureTool[UserRequest, MfaEvents]):
    metadata = ToolMetadata(
        name="get_mfa_events",
        version=TOOL_VERSION,
        access=ToolAccess.READ_ONLY,
        data_classification=DataClassification.SYNTHETIC_DEMO,
        timeout_ms=DEFAULT_TIMEOUT_MS,
        request_model=UserRequest,
        response_model=MfaEvents,
    )

    def execute(self, request: UserRequest) -> ToolOutcome[MfaEvents]:
        if not any(item.user_id == request.user_id for item in self._dataset.identities):
            return self._not_found("identity", request.user_id)
        events = tuple(
            sorted(
                (item for item in self._dataset.mfa_events if item.user_id == request.user_id),
                key=lambda item: (item.occurred_at, item.mfa_event_id),
                reverse=True,
            )
        )
        return self._found(MfaEvents(user_id=request.user_id, events=events))


class FixtureRelatedAlertsTool(_FixtureTool[UserRequest, RelatedAlerts]):
    metadata = ToolMetadata(
        name="find_related_alerts",
        version=TOOL_VERSION,
        access=ToolAccess.READ_ONLY,
        data_classification=DataClassification.SYNTHETIC_DEMO,
        timeout_ms=DEFAULT_TIMEOUT_MS,
        request_model=UserRequest,
        response_model=RelatedAlerts,
    )

    def execute(self, request: UserRequest) -> ToolOutcome[RelatedAlerts]:
        if not any(item.user_id == request.user_id for item in self._dataset.identities):
            return self._not_found("identity", request.user_id)
        mapping = next(
            (item for item in self._dataset.related_alerts if item.user_id == request.user_id),
            None,
        )
        alert_ids = mapping.alert_ids if mapping else ()
        alerts_by_id = {item.alert_id: item for item in self._dataset.alerts}
        alerts = tuple(
            sorted(
                (
                    RelatedAlertSummary(
                        alert_id=alerts_by_id[alert_id].alert_id,
                        title=alerts_by_id[alert_id].title,
                        source_severity=alerts_by_id[alert_id].source_severity,
                        occurred_at=alerts_by_id[alert_id].occurred_at,
                    )
                    for alert_id in alert_ids
                ),
                key=lambda item: (item.occurred_at, item.alert_id),
                reverse=True,
            )
        )
        return self._found(RelatedAlerts(user_id=request.user_id, alerts=alerts))


class FixtureIdentityContextTool(_FixtureTool[UserRequest, IdentityContext]):
    metadata = ToolMetadata(
        name="get_identity_context",
        version=TOOL_VERSION,
        access=ToolAccess.READ_ONLY,
        data_classification=DataClassification.SYNTHETIC_DEMO,
        timeout_ms=DEFAULT_TIMEOUT_MS,
        request_model=UserRequest,
        response_model=IdentityContext,
    )

    def execute(self, request: UserRequest) -> ToolOutcome[IdentityContext]:
        identity = next(
            (item for item in self._dataset.identities if item.user_id == request.user_id),
            None,
        )
        return self._found(identity) if identity else self._not_found("identity", request.user_id)
