"""Traceable evidence and tool-call references; no tool behavior lives here."""

from security_triage_agent.domain._base import (
    DomainModel,
    Identifier,
    ShortText,
    UtcDatetime,
    Version,
)


class EvidenceReference(DomainModel):
    """Reference to evidence with collection and source provenance."""

    evidence_id: Identifier
    source_type: Identifier
    source_reference: Identifier
    collected_at: UtcDatetime
    source_version: Version
    summary: ShortText
    tool_invocation_id: Identifier | None = None


class ToolCallReference(DomainModel):
    """Sanitized reference to a future persisted tool invocation."""

    invocation_id: Identifier
    tool_name: Identifier
    tool_version: Version
    called_at: UtcDatetime
    summary: ShortText
