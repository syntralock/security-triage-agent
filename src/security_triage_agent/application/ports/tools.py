"""Generic read-only evidence-tool port and result envelopes."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, Field

from security_triage_agent.domain._base import DomainModel, Identifier, ShortText, Version


class ToolAccess(StrEnum):
    """Whether a tool can read or mutate an external system."""

    READ_ONLY = "READ_ONLY"
    READ_WRITE = "READ_WRITE"


class DataClassification(StrEnum):
    """Data classification declared by a tool adapter."""

    SYNTHETIC_DEMO = "SYNTHETIC_DEMO"


class ToolStatus(StrEnum):
    """Expected semantic result states for evidence lookups."""

    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"


class ToolProvenance(DomainModel):
    """Stable source identity included with every tool outcome."""

    tool_name: Identifier
    tool_version: Version
    fixture_version: Version


class Found[ResultT: BaseModel](DomainModel):
    """Successful typed lookup result."""

    status: Literal[ToolStatus.FOUND] = ToolStatus.FOUND
    provenance: ToolProvenance
    data: ResultT


class NotFound(DomainModel):
    """Expected, typed absence of a fixture entity or evidence record."""

    status: Literal[ToolStatus.NOT_FOUND] = ToolStatus.NOT_FOUND
    provenance: ToolProvenance
    resource_type: Identifier
    identifier: Identifier
    message: ShortText


type ToolOutcome[ResultT: BaseModel] = Annotated[
    Found[ResultT] | NotFound,
    Field(discriminator="status"),
]


@dataclass(frozen=True, slots=True)
class ToolMetadata[RequestT: BaseModel, ResponseT: BaseModel]:
    """Static contract metadata exposed for a future gateway registry."""

    name: str
    version: str
    access: ToolAccess
    data_classification: DataClassification
    timeout_ms: int
    request_model: type[RequestT]
    response_model: type[ResponseT]

    @property
    def input_schema(self) -> dict[str, object]:
        return self.request_model.model_json_schema()

    @property
    def output_schema(self) -> dict[str, object]:
        return self.response_model.model_json_schema()


class EvidenceTool[RequestT: BaseModel, ResponseT: BaseModel](Protocol):
    """Synchronous typed evidence source with no authorization responsibility."""

    @property
    def metadata(self) -> ToolMetadata[RequestT, ResponseT]: ...

    def execute(self, request: RequestT) -> ToolOutcome[ResponseT]: ...
