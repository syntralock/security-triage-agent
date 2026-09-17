"""Typed requests and responses for the seven approved evidence tools."""

from enum import StrEnum

from pydantic import Field, IPvAnyAddress

from security_triage_agent.domain._base import (
    DomainModel,
    Identifier,
    ShortText,
    UtcDatetime,
)
from security_triage_agent.domain.triage import Severity


class RiskLevel(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RiskState(StrEnum):
    NONE = "NONE"
    AT_RISK = "AT_RISK"
    REMEDIATED = "REMEDIATED"


class SignInStatus(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


class ComplianceState(StrEnum):
    COMPLIANT = "COMPLIANT"
    NONCOMPLIANT = "NONCOMPLIANT"
    UNKNOWN = "UNKNOWN"


class IpReputationCategory(StrEnum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


class MfaEventStatus(StrEnum):
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    FAILED = "FAILED"


class PrivilegeLevel(StrEnum):
    STANDARD = "STANDARD"
    PRIVILEGED = "PRIVILEGED"


class UserRequest(DomainModel):
    user_id: Identifier


class DeviceRequest(DomainModel):
    device_id: Identifier


class IpAddressRequest(DomainModel):
    ip_address: IPvAnyAddress


class SignInEvent(DomainModel):
    sign_in_id: Identifier
    user_id: Identifier
    device_id: Identifier
    ip_address: IPvAnyAddress
    occurred_at: UtcDatetime
    status: SignInStatus
    authentication_method: Identifier
    location: ShortText


class RecentSignIns(DomainModel):
    user_id: Identifier
    reference_time: UtcDatetime
    window_started_at: UtcDatetime
    sign_ins: tuple[SignInEvent, ...]


class UserRisk(DomainModel):
    user_id: Identifier
    risk_level: RiskLevel
    risk_state: RiskState
    observed_at: UtcDatetime
    summary: ShortText


class DeviceContext(DomainModel):
    device_id: Identifier
    display_name: ShortText
    operating_system: ShortText
    compliance_state: ComplianceState
    managed: bool
    last_seen_at: UtcDatetime
    owner_user_ids: tuple[Identifier, ...]


class IpReputation(DomainModel):
    ip_address: IPvAnyAddress
    category: IpReputationCategory
    confidence_score: int = Field(ge=0, le=100)
    observed_at: UtcDatetime
    summary: ShortText


class MfaEvent(DomainModel):
    mfa_event_id: Identifier
    user_id: Identifier
    occurred_at: UtcDatetime
    method: Identifier
    status: MfaEventStatus
    source_sign_in_id: Identifier


class MfaEvents(DomainModel):
    user_id: Identifier
    events: tuple[MfaEvent, ...]


class RelatedAlertSummary(DomainModel):
    alert_id: Identifier
    title: ShortText
    source_severity: Severity
    occurred_at: UtcDatetime


class RelatedAlerts(DomainModel):
    user_id: Identifier
    alerts: tuple[RelatedAlertSummary, ...]


class IdentityContext(DomainModel):
    user_id: Identifier
    display_name: ShortText
    principal_name: ShortText
    role: ShortText
    enabled: bool
    privilege_level: PrivilegeLevel
    device_ids: tuple[Identifier, ...]
