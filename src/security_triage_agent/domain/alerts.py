"""Provider-neutral security alert contract."""

from pydantic import model_validator

from security_triage_agent.domain._base import (
    DomainModel,
    Identifier,
    NonEmptyText,
    Sha256Digest,
    ShortText,
    UtcDatetime,
    Version,
)
from security_triage_agent.domain.entities import EntityReference
from security_triage_agent.domain.triage import Severity


class SourcePayloadReference(DomainModel):
    """Immutable provenance reference to an original provider payload."""

    reference_id: Identifier
    payload_digest: Sha256Digest


class SecurityAlert(DomainModel):
    """Normalized alert data with provider payloads kept outside the domain."""

    alert_id: Identifier
    source: Identifier
    source_severity: Severity
    title: ShortText
    description: NonEmptyText
    occurred_at: UtcDatetime
    detected_at: UtcDatetime
    entities: tuple[EntityReference, ...]
    provider_schema_version: Version
    original_payload: SourcePayloadReference

    @model_validator(mode="after")
    def validate_alert(self) -> "SecurityAlert":
        if self.detected_at < self.occurred_at:
            raise ValueError("detected_at must not be earlier than occurred_at")
        scope_keys = [entity.scope_key for entity in self.entities]
        if len(scope_keys) != len(set(scope_keys)):
            raise ValueError("alert entities must be unique")
        return self

    def contains_entity(self, entity: EntityReference) -> bool:
        """Return whether an entity is inside this alert's normalized scope."""

        return entity.scope_key in {candidate.scope_key for candidate in self.entities}
