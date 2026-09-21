"""Provider-neutral domain contracts for security alert triage."""

from security_triage_agent.domain.actions import (
    ActionLifecycle,
    ActionProposal,
    ActionRecommendation,
    ActionReference,
    ActionState,
)
from security_triage_agent.domain.alerts import SecurityAlert, SourcePayloadReference
from security_triage_agent.domain.approvals import (
    ApprovalDecision,
    ApprovalLifecycle,
    ApprovalRecord,
    ApprovalState,
)
from security_triage_agent.domain.entities import (
    DeviceEntityReference,
    EntityReference,
    EntityType,
    IpAddressEntityReference,
    UserEntityReference,
)
from security_triage_agent.domain.evidence import EvidenceReference, ToolCallReference
from security_triage_agent.domain.states import TriageExecution, TriageExecutionState
from security_triage_agent.domain.triage import Disposition, Severity, TriageResult

__all__ = [
    "ActionLifecycle",
    "ActionProposal",
    "ActionRecommendation",
    "ActionReference",
    "ActionState",
    "ApprovalDecision",
    "ApprovalLifecycle",
    "ApprovalRecord",
    "ApprovalState",
    "DeviceEntityReference",
    "Disposition",
    "EntityReference",
    "EntityType",
    "EvidenceReference",
    "IpAddressEntityReference",
    "SecurityAlert",
    "Severity",
    "SourcePayloadReference",
    "ToolCallReference",
    "TriageExecution",
    "TriageExecutionState",
    "TriageResult",
    "UserEntityReference",
]
