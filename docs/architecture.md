# System Architecture

Status: approved on 2026-09-17. Milestone implementation remains gated by `docs/implementation-plan.md`.

## 1. Requirements analysis

The product is a case-processing system, not a conversational assistant. Its primary unit of work is a triage execution against one normalized synthetic alert. A successful execution gathers bounded evidence, produces a typed assessment, passes that assessment through deterministic policy, and persists enough information to reconstruct what happened.

The main architectural tension is that flexible model reasoning is useful for evidence synthesis and recommendations, while security controls must remain predictable and enforceable. The design therefore puts the model inside a constrained orchestration loop and surrounds it with code-owned schemas, allowlists, budgets, policy checks, approvals, and an append-only audit trail.

The first release should be a modular monolith. Separate services would add operational and transactional complexity without improving the current threat boundary. Clean ports allow the database, model provider, evidence sources, and action executors to be replaced later.

### Required capabilities

- Accept Sentinel-, Defender-, and Entra-style synthetic alert payloads through explicit adapters.
- Normalize alerts into a provider-neutral domain model.
- Run an idempotent, bounded triage execution with traceable status transitions.
- Allow the reasoning component to request only registered, read-only evidence tools.
- Return a strongly typed triage result with the required fields and controlled enums.
- Apply deterministic post-reasoning policy, including escalation and action-approval rules.
- Persist the source alert, execution, every tool request/result, decisions, approvals, and action outcomes.
- Run deterministic tests without API access and optional model-backed evaluations with pinned configuration.

### Key quality attributes

- **Safety:** deny by default; no implicit permission follows from model output.
- **Auditability:** reconstruct every execution from durable, correlated records.
- **Repeatability:** version fixtures, scenarios, prompts, policies, and model configuration.
- **Replaceability:** isolate FastAPI, SQLAlchemy, fixture tools, and OpenAI behind boundaries.
- **Operability:** structured logs, health checks, timeouts, failure states, and measurable latency.

## 2. Proposed component model

```text
HTTP / server-rendered UI
        |
        v
Provider adapters -> Alert normalization -> Triage application service
                                             |       |       |
                                             |       |       +-> Audit repository
                                             |       +----------> Policy engine
                                             +------------------> Agent orchestrator
                                                                       |
                                                     +-----------------+----------------+
                                                     |                                  |
                                               Agent reasoner                      Tool gateway
                                              (OpenAI or fake)                         |
                                                                                Tool registry
                                                                                     |
                                                                         Synthetic fixture adapters

Human review UI/API -> Approval service -> Action policy -> Action executor registry
                                                        (safe stub initially)
```

### API and presentation

FastAPI owns transport concerns: request validation, authentication hooks, correlation IDs, response mapping, and error mapping. Server-rendered pages call the same application services as the JSON API. Routes contain no triage or authorization decisions.

### Alert ingestion and normalization

Each provider adapter validates an explicit synthetic input schema and maps it to `SecurityAlert`. Preserve the original payload for audit, tagged with provider and schema version. The normalized model should include stable entity references (user, device, IP), timestamps, source, severity, title, and descriptive evidence. Unknown fields must not become instructions or executable configuration.

### Triage application service

This is the use-case boundary. It creates an execution, enforces idempotency, invokes orchestration, applies final policy, and commits the result and audit events. Expected statuses include `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, and `NEEDS_REVIEW`. A terminal result is immutable; a retriage creates a new execution linked to its predecessor.

### Agent orchestrator

The orchestrator implements a bounded state machine, not an open-ended autonomous loop:

1. Build a minimal prompt/context from the normalized alert and policy-owned tool descriptions.
2. Ask the reasoner for typed tool requests or a typed candidate assessment.
3. Validate requested tool name and arguments through the tool gateway.
4. Enforce per-tool and total call budgets, timeouts, entity scope, and duplicate-call rules.
5. Persist the tool request and sanitized result before continuing.
6. Stop at a fixed iteration/deadline limit.
7. Validate the candidate assessment and pass it to deterministic policy.
8. On invalid output, exhausted budgets, or incomplete evidence, fail safely to a review state.

The orchestrator never exposes callable application objects directly to the model.

### Agent reasoner port

`AgentReasoner` accepts a versioned reasoning request and returns a strict union such as `ToolCallRequest | CandidateTriage`. Implementations:

- `OpenAIReasoner`: the production adapter, using structured outputs/tool calling through the OpenAI SDK.
- `FakeReasoner`: deterministic scripted behavior for unit and integration tests.
- Optionally, a rule-based baseline for evaluation comparisons.

The persisted record should include provider, model identifier, model/prompt version, request correlation, token/latency metadata where available, and a sanitized response or response hash according to retention policy.

### Evidence tool gateway and registry

Tools implement a common typed interface with metadata: name, version, input schema, output schema, data classification, read/write capability, timeout, and required scope. The registry initially contains only:

- `get_recent_signins(user_id)`
- `get_user_risk(user_id)`
- `get_device_context(device_id)`
- `get_ip_reputation(ip_address)`
- `get_mfa_events(user_id)`
- `find_related_alerts(user_id)`
- `get_identity_context(user_id)`

The gateway validates arguments, confirms identifiers belong to the alert's allowed entity scope, enforces budgets and timeouts, invokes the adapter, validates output, redacts logged fields, and emits audit records. Fixture adapters read versioned, deterministic synthetic datasets. Returning “not found” is a typed result, not an exception-shaped ambiguity.

### Deterministic policy engine

Policy code receives the candidate assessment plus execution facts and produces an enforced result. It owns:

- allowed disposition and severity values;
- confidence range and normalization;
- minimum evidence and escalation conditions;
- action lookup and risk classification;
- the final `actions_requiring_approval` set;
- denial of unknown actions;
- fail-safe behavior for missing/invalid reasoning or tool failures.

The policy version is persisted on every execution. Initially policy can be ordinary typed Python with exhaustive tests; a rule engine is unnecessary until policy complexity justifies it.

### Action catalog, approval, and execution

Recommendations use stable action identifiers, typed target/parameters, and human-readable rationale. A central catalog assigns each action a risk level and approval requirement. The six named high-impact actions are always approval-required.

Approval is a separate workflow and durable record with reviewer identity, decision, timestamp, reason, policy version, and a digest of the exact action request. An approved decision requires an expiry defining the lifetime of granted authorization; a rejected decision must not have an expiry because no authorization was granted. The executor revalidates the action binding, policy, authorization, and expiry immediately before running. Initially, use a `NoOpActionExecutor` or synthetic simulator so the project demonstrates the boundary without touching real systems.

Recommended state flow:

```text
PROPOSED -> PENDING_APPROVAL -> APPROVED -> EXECUTING -> SUCCEEDED
                            \-> REJECTED
                            \-> EXPIRED
                                              \-> FAILED
```

Invalid transitions are rejected in code. Approval and execution actors must be distinct roles, even if development authentication uses synthetic identities.

### Persistence and audit

Use SQLAlchemy 2.x mappings and explicit repositories/unit-of-work boundaries. Use Alembic from the first schema. Suggested records:

- `alerts`: normalized fields, original payload, provider/schema version, payload digest.
- `triage_executions`: lifecycle, versions, timing, failure category, predecessor.
- `tool_invocations`: sequence, tool/version, validated arguments, outcome, result, timing.
- `triage_results`: enforced typed result and candidate-result reference.
- `recommended_actions`: catalog ID, target, parameters, risk, status.
- `approval_decisions`: immutable approval/rejection facts and action digest.
- `action_executions`: attempts and sanitized outcomes.
- `audit_events`: append-only event envelope with actor, type, entity, timestamp, correlation ID, and payload.
- `evaluation_runs` and `evaluation_case_results`: reproducibility metadata and metrics.

Normalized tables support queries while append-only audit events support reconstruction. Audit writes belong in the same database transaction as the state change they describe. For future external event export, add an outbox rather than dual-writing. Database constraints should enforce important uniqueness and transition-related invariants where feasible.

## 3. Triage result contract

The API result is a strict Pydantic model containing:

- `alert_id`
- `disposition`: `BENIGN | SUSPICIOUS | MALICIOUS | NEEDS_REVIEW`
- `confidence`: model-reported confidence bounded to `0.0..1.0`; preserve the model-provided precision in storage and use the unrounded value for evaluation and calibration work. This is not a calibrated probability unless future evaluation demonstrates calibration.
- `severity`: assessed triage severity using the closed enum `INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL`; source alert severity is stored separately and is never overwritten or discarded.
- `evidence`: typed evidence references, not only prose
- `reasoning_summary`: concise, non-chain-of-thought decision rationale
- `recommended_actions`: typed action proposals
- `actions_requiring_approval`: action IDs derived by policy
- `escalation_required`
- `escalation_reason`: required when escalation is true
- `tool_calls`: stable audit/evidence references plus concise sanitized summaries matching persisted invocations; complete synthetic results remain in the authorized audit record and are not exposed unnecessarily
- `timestamp`: UTC and timezone-aware

Do not request or store private chain-of-thought. The reasoning summary should cite evidence references and decision factors sufficient for a reviewer to understand the outcome.

### Domain contract decisions

- Domain models are immutable, reject unknown fields, and contain no framework, persistence, provider, network, filesystem, or execution behavior.
- Aware timestamps in any timezone are accepted at construction and normalized to UTC; naive timestamps are rejected.
- Confidence is represented as `Decimal`, preserving supplied precision across domain serialization round trips.
- Alert scope uses discriminated user, device, and IP-address references. IP addresses are normalized by value.
- Evidence may originate from a tool or another source such as the source alert. Tool-origin evidence must reference a tool call included in the same triage result.
- Action parameters are structured JSON values and are deep-frozen after validation. The action digest is SHA-256 over canonical JSON containing the catalog action identifier, normalized target, and parameters. Action ID and reviewer-facing rationale are intentionally outside the digest; approvals bind both the stable action ID and digest.
- `actions_requiring_approval` contains typed action ID/digest references and may only reference matching recommended actions. Policy—not an action proposal—will decide which actions require approval in Milestone 6.
- Lifecycle transition methods return new immutable state objects and reject transitions not listed in the approved state maps.
- Approved decisions require a future expiry and may later transition to `EXPIRED`. Rejected decisions have no expiry while preserving the reviewer, decision time, reason, policy version, and action binding as immutable historical facts.

## 4. Security and architectural decisions

### Approved decisions

1. **Modular monolith first.** It permits transactional audit writes and simple local operation while interfaces preserve future extraction paths.
2. **Model output is advisory.** Deterministic code owns policy, authorization, approval, and action execution.
3. **Read-only agent tool set.** Evidence collection and remediation have separate registries, identities, and workflows.
4. **Default deny.** Unknown tool/action names, malformed output, entity-scope violations, and policy ambiguity are rejected.
5. **Bounded execution.** Fixed tool-call count, iteration count, per-call timeout, overall deadline, and context-size limits prevent runaway cost and denial of service.
6. **Prompt-injection-resistant data handling.** Alert and evidence content is labeled untrusted, never interpolated into system/developer instructions, and cannot expand capabilities.
7. **Evidence provenance.** Every evidence item references a persisted tool invocation, source version, and collection time.
8. **Immutable terminal results.** Corrections and retriage create linked records rather than rewriting history.
9. **Explicit idempotency.** Alert ingestion and execution creation accept idempotency keys and database uniqueness constraints.
10. **Safe initial action adapter.** The first implementation simulates actions only; real integrations require a separate reviewed milestone.
11. **No sensitive data in model context by default.** Only the minimum synthetic fields required for a decision are included.
12. **Offline deterministic test path.** CI uses a fake reasoner and fixture tools; live-model evaluation is opt-in and separately reported.
13. **Separate source and assessed severity.** Provider severity remains on the source alert; triage-result `severity` is the assessed severity.
14. **Model-reported confidence.** Confidence is an unrounded decimal in `0.0..1.0`; presentation may round it, but evaluation uses the stored value and must not describe it as calibrated without evidence.
15. **Limited normal tool output.** Normal API/UI responses expose references and sanitized summaries, while complete synthetic results require authorized audit access.
16. **Replaceable development identity.** Initial authentication uses an explicitly development-only synthetic principal behind an authorization interface, so a production identity provider can replace it without changing domain or policy logic.
17. **Initial audit integrity.** State changes and append-only audit events share a transaction. Hash chaining is deferred, while the event model remains compatible with signed export or immutable external storage.
18. **Reasoning is not execution authority.** The agent may investigate and recommend but cannot authorize, approve, execute privileged changes, alter policy, register capabilities, or expand permissions. Initial remediation is simulation-only.

### Threats to cover in the threat model

- Prompt injection embedded in alert text or tool results.
- Hallucinated tools, entities, evidence, actions, and approvals.
- Cross-alert or future cross-tenant data leakage through identifiers or caches.
- Replay, duplication, stale approvals, and time-of-check/time-of-use changes.
- Audit deletion/tampering and partial writes.
- Oversized inputs, tool-call loops, resource exhaustion, and provider timeout.
- Sensitive-value leakage through logs, traces, errors, prompts, or model-provider retention.
- Malicious or compromised fixture/integration adapters returning executable-looking content.
- Broken access control in review, approval, and execution APIs.
- Supply-chain and dependency compromise.

## 5. Responsibilities that must not use an LLM

- Authentication, reviewer identity, roles, and authorization.
- Request/schema validation and provider payload normalization.
- Entity ownership/scope checks and any tenant isolation.
- Tool registration, allowlisting, argument validation, call budgets, timeouts, and invocation.
- SQL/query construction, database constraints, transactions, and migrations.
- Action risk classification and whether approval is required.
- Approval creation, validity, expiry, digest matching, and state transitions.
- Remediation execution and verification.
- Audit event creation, ordering, durability, integrity controls, and retention.
- Idempotency, retry rules, concurrency control, and rate limiting.
- Confidence range enforcement, enum validation, and fail-safe escalation.
- Evaluation ground truth, scoring, confusion-matrix metrics, and pass/fail thresholds.
- Secret handling, redaction, logging policy, and environment configuration.

An LLM is appropriate for synthesizing heterogeneous evidence, proposing a supported disposition, producing a concise rationale, and recommending cataloged actions. Those outputs remain untrusted proposals until validated.

## 6. Evaluation architecture

A scenario is a versioned bundle containing a synthetic alert, referenced fixture dataset version, expected disposition (or allowed set), escalation expectation, required/allowed/forbidden tool calls, and optional expected evidence/action constraints. Do not overfit every scenario to one exact call order unless order is semantically required.

The runner executes scenarios through the same application service used by the API. It records per-case output, policy/prompt/model/fixture versions, duration, tool calls, and validation failures. A deterministic scorer calculates:

- disposition accuracy;
- false-positive and false-negative rates with an explicitly documented positive class;
- escalation accuracy;
- tool-selection precision/recall (more informative than a single accuracy value);
- processing-time percentiles and timeout rate.

Evaluation reports should separate deterministic fake-reasoner contract tests from model-quality runs. Model-quality gates need repeated runs and tolerance-based thresholds because model behavior may vary.

## 7. Agent authority boundary

The agent has reasoning and recommendation authority only. It may investigate alerts, request allowlisted read-only evidence tools, correlate and synthesize evidence, propose a disposition and assessed severity, report model confidence, produce a concise reasoning summary, recommend registered actions, and recommend escalation.

The agent cannot authorize or approve actions, execute privileged changes directly, bypass policy or approval, expand its permissions, register tools, invoke arbitrary functions or destinations, change action risk, remove approval requirements, fabricate approval, or treat alert/evidence content as instructions.

Deterministic application code owns authentication, authorization, tool registration and validation, entity/data scope, budgets and timeouts, policy, action risk, approval requirements and validity, execution, audit recording, state transitions, and evaluation scoring.

If the model is unavailable, returns invalid output, exceeds execution bounds, requests prohibited capabilities, or lacks sufficient evidence, policy fails safely—normally to a persisted `NEEDS_REVIEW` result when a valid reviewable result can be recorded. `FAILED` is reserved for executions that cannot produce or persist a valid terminal result.
