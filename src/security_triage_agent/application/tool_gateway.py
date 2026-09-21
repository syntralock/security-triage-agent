"""Deterministic security boundary for proposed evidence-tool invocations."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from time import monotonic_ns
from typing import Any

from pydantic import Field, TypeAdapter, ValidationError, model_validator

from security_triage_agent.application.ports.tools import Found, NotFound, ToolAccess, ToolStatus
from security_triage_agent.application.tool_registry import ToolRegistry
from security_triage_agent.domain._base import DomainModel, Identifier, ShortText, UtcDatetime
from security_triage_agent.domain.alerts import SecurityAlert
from security_triage_agent.domain.entities import EntityType


class GatewayStatus(StrEnum):
    SUCCESS = "SUCCESS"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    INVALID_REQUEST = "INVALID_REQUEST"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    READ_ONLY_REQUIRED = "READ_ONLY_REQUIRED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    DUPLICATE_REQUEST = "DUPLICATE_REQUEST"
    TIMEOUT = "TIMEOUT"
    INVALID_ADAPTER_RESULT = "INVALID_ADAPTER_RESULT"
    ADAPTER_FAILURE = "ADAPTER_FAILURE"


class AuthorizationResult(StrEnum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"


class ProposedToolRequest(DomainModel):
    """Validated semantics with an application-assigned invocation identifier."""

    call_id: Identifier
    tool_name: Identifier
    arguments: dict[str, object]


class GatewayLimits(DomainModel):
    """Trusted bounds supplied by application configuration or policy."""

    total_calls: int = Field(ge=1, le=100)
    per_tool_calls: int = Field(ge=1, le=50)
    max_input_bytes: int = Field(default=4096, ge=64, le=1_000_000)
    max_output_bytes: int = Field(default=65_536, ge=64, le=10_000_000)
    timeout_cap_ms: int = Field(default=5_000, ge=1, le=60_000)


class EntityScope(DomainModel):
    """Normalized entity keys established from a trusted alert."""

    keys: frozenset[str]

    @classmethod
    def from_alert(cls, alert: SecurityAlert) -> EntityScope:
        return cls(keys=frozenset(entity.scope_key for entity in alert.entities))


class GatewayResult(DomainModel):
    """Sanitized result returned across the gateway boundary."""

    call_id: Identifier
    tool_name: Identifier
    status: GatewayStatus
    authorization: AuthorizationResult
    result: dict[str, object] | None = None
    failure_message: ShortText | None = None

    @model_validator(mode="after")
    def validate_shape(self) -> GatewayResult:
        if self.status is GatewayStatus.SUCCESS and self.result is None:
            raise ValueError("successful gateway result requires result")
        if self.status is not GatewayStatus.SUCCESS and self.result is not None:
            raise ValueError("failed gateway result must not contain result")
        return self


class ToolInvocationRecord(DomainModel):
    """In-memory audit hook emitted for every attempted call."""

    execution_id: Identifier
    correlation_id: Identifier
    call_id: Identifier
    tool_name: Identifier
    sanitized_arguments: dict[str, object]
    authorization: AuthorizationResult
    outcome: GatewayStatus
    started_at: UtcDatetime
    completed_at: UtcDatetime
    duration_ms: int = Field(ge=0)
    failure_category: GatewayStatus | None = None


@dataclass(slots=True)
class ToolExecutionContext:
    """Trusted scope, limits, and mutable per-execution accounting state."""

    execution_id: str
    correlation_id: str
    entity_scope: EntityScope
    limits: GatewayLimits
    invocation_records: list[ToolInvocationRecord] = field(default_factory=list)
    _total_calls: int = 0
    _per_tool_calls: Counter[str] = field(default_factory=Counter)
    _seen_calls: set[str] = field(default_factory=set)

    @property
    def total_calls_used(self) -> int:
        return self._total_calls


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ToolGateway:
    """Validate, authorize, bound, invoke, and validate evidence-tool proposals."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        now: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], int] = monotonic_ns,
    ) -> None:
        self._registry = registry
        self._now = now
        self._monotonic = monotonic

    def invoke(self, proposal: ProposedToolRequest, context: ToolExecutionContext) -> GatewayResult:
        started_at = self._now()
        started_ns = self._monotonic()
        sanitized_arguments: dict[str, object] = {}
        authorization = AuthorizationResult.DENIED

        def finish(
            status: GatewayStatus,
            *,
            message: str | None = None,
            result: dict[str, object] | None = None,
        ) -> GatewayResult:
            completed_at = self._now()
            duration_ms = max(0, (self._monotonic() - started_ns) // 1_000_000)
            record = ToolInvocationRecord(
                execution_id=context.execution_id,
                correlation_id=context.correlation_id,
                call_id=proposal.call_id,
                tool_name=proposal.tool_name,
                sanitized_arguments=sanitized_arguments,
                authorization=authorization,
                outcome=status,
                started_at=started_at,
                completed_at=completed_at,
                duration_ms=duration_ms,
                failure_category=None if status is GatewayStatus.SUCCESS else status,
            )
            context.invocation_records.append(record)
            return GatewayResult(
                call_id=proposal.call_id,
                tool_name=proposal.tool_name,
                status=status,
                authorization=authorization,
                result=result,
                failure_message=message,
            )

        tool = self._registry.lookup(proposal.tool_name)
        if tool is None:
            return finish(GatewayStatus.TOOL_NOT_FOUND, message="Tool is not registered")
        if tool.metadata.access is not ToolAccess.READ_ONLY:
            return finish(
                GatewayStatus.READ_ONLY_REQUIRED,
                message="Only read-only evidence tools are permitted",
            )
        if self._encoded_size(proposal.arguments) > context.limits.max_input_bytes:
            return finish(GatewayStatus.INVALID_REQUEST, message="Tool arguments exceed size limit")
        try:
            request = tool.metadata.request_model.model_validate(proposal.arguments, strict=True)
        except ValidationError:
            return finish(GatewayStatus.INVALID_REQUEST, message="Tool arguments are invalid")
        sanitized_arguments = request.model_dump(mode="json")
        scope_key = self._scope_key(sanitized_arguments)
        if scope_key is None or scope_key not in context.entity_scope.keys:
            return finish(GatewayStatus.OUT_OF_SCOPE, message="Requested entity is out of scope")

        fingerprint = self._fingerprint(proposal.tool_name, sanitized_arguments)
        if fingerprint in context._seen_calls:
            return finish(
                GatewayStatus.DUPLICATE_REQUEST, message="Duplicate call is not permitted"
            )
        if context._total_calls >= context.limits.total_calls:
            return finish(GatewayStatus.BUDGET_EXCEEDED, message="Total call budget exhausted")
        if context._per_tool_calls[proposal.tool_name] >= context.limits.per_tool_calls:
            return finish(GatewayStatus.BUDGET_EXCEEDED, message="Per-tool call budget exhausted")

        context._seen_calls.add(fingerprint)
        context._total_calls += 1
        context._per_tool_calls[proposal.tool_name] += 1
        authorization = AuthorizationResult.ALLOWED
        timeout_ms = min(tool.metadata.timeout_ms, context.limits.timeout_cap_ms)
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="evidence-tool")
        future = executor.submit(tool.execute, request)
        try:
            raw_outcome = future.result(timeout=timeout_ms / 1000)
        except FutureTimeoutError:
            future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            return finish(GatewayStatus.TIMEOUT, message="Tool execution timed out")
        except Exception:
            executor.shutdown(wait=False, cancel_futures=True)
            return finish(GatewayStatus.ADAPTER_FAILURE, message="Tool execution failed")
        executor.shutdown(wait=True)

        try:
            status = getattr(raw_outcome, "status", None)
            outcome_model: Any
            if status is ToolStatus.FOUND:
                response_model = tool.metadata.response_model
                outcome_model = Found[response_model]  # type: ignore[valid-type]
            elif status is ToolStatus.NOT_FOUND:
                outcome_model = NotFound
            else:
                raise ValueError("unknown tool result status")
            outcome_adapter: TypeAdapter[Any] = TypeAdapter(outcome_model)
            validated = outcome_adapter.validate_python(raw_outcome, strict=True)
            serialized = validated.model_dump(mode="json")
        except (ValidationError, TypeError, ValueError):
            return finish(
                GatewayStatus.INVALID_ADAPTER_RESULT,
                message="Tool returned an invalid result",
            )
        if self._encoded_size(serialized) > context.limits.max_output_bytes:
            return finish(
                GatewayStatus.INVALID_ADAPTER_RESULT,
                message="Tool result exceeds size limit",
            )
        return finish(GatewayStatus.SUCCESS, result=serialized)

    @staticmethod
    def _encoded_size(value: object) -> int:
        try:
            return len(
                json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            )
        except (TypeError, ValueError):
            return 1_000_001

    @staticmethod
    def _fingerprint(tool_name: str, arguments: dict[str, object]) -> str:
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return f"{tool_name}:{canonical}"

    @staticmethod
    def _scope_key(arguments: dict[str, object]) -> str | None:
        if "user_id" in arguments:
            return f"{EntityType.USER.value}:{arguments['user_id']}"
        if "device_id" in arguments:
            return f"{EntityType.DEVICE.value}:{arguments['device_id']}"
        if "ip_address" in arguments:
            return f"{EntityType.IP_ADDRESS.value}:{arguments['ip_address']}"
        return None
