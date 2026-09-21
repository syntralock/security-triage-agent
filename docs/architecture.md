# System Architecture

Status: approved on 2026-09-17. Milestone implementation remains gated by `docs/implementation-plan.md`.

Milestone 11 adds `OpenAIReasoner` as an optional infrastructure adapter behind the unchanged `AgentReasoner` port. The OpenAI model is a reasoning component, not a security authority. Trusted configuration selects either the offline demo adapter or OpenAI; HTTP callers cannot select a provider, model, prompt, key, or implementation, and no automatic fallback can change evaluation identity.

The adapter uses the official OpenAI Python SDK 2.x and Responses API `responses.parse` with a strict Pydantic output model, following the official [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs). Requests set `store=False`, consistent with the official [data controls documentation](https://developers.openai.com/api/docs/guides/your-data), disable SDK retries, apply a 25-second configured timeout capped below the 30-second orchestration deadline, and bound output tokens. The configured default/example model is `gpt-5.6-luna`, selected as a current cost-sensitive reasoning model; model identity is configuration, not a code assumption.

The frozen `openai-l1-v1` instruction contract treats all alert/evidence text as untrusted data, forbids invented references and private chain-of-thought, allows exactly one proposed next step, and states that recommendations confer no approval or execution authority. The reviewed `openai-l1-v2` contract is a separately hashed, explicitly selected alternative; it adds operational definitions for evidence sufficiency, disposition, independently assessed severity, escalation, confidence, and minimum-necessary action selection. Unknown prompt versions fail closed, prompt selection comes only from trusted process configuration, and v1 serialization remains unchanged.

The provider receives only a bounded `ReasonerContext` serialization. V2 adds a model-visible copy of the exact alert-derived entity scope used by `ToolGateway` and trusted advisory semantics derived from the deterministic action catalog. Neither copy grants authority: seven schema variants represent read-only evidence proposals, the SDK receives no tool definitions or Python callables, and `ToolGateway` independently validates allowlisting, arguments, budgets, duplicates, and its authoritative entity scope. Candidate output selects evidence and tool-call references by opaque identifier, and the adapter maps exact identifiers back to immutable objects from the current context; unknown identifiers fail closed. Policy validates every semantic action proposal and generates canonical action identity.

For v2 only, the provider-facing projection removes provider payload provenance fields and neutralizes artificial-environment labels such as synthetic/demo/test/fixture wording, expected-baseline prose, and artificial hostname/identifier cues. Security-relevant facts, typed values, and identifiers needed for scope are preserved. This transformation does not mutate the normalized alert, fixture result, durable audit record, evaluation ground truth, or v1 context. Synthetic-only transmission remains an external safety requirement rather than evidence for a security conclusion.

Malformed/refused responses and timeout, authentication, rate-limit, unavailable-service, connection, or unexpected SDK failures become categorized sanitized adapter errors. Existing orchestration turns them into a durable policy-safe `NEEDS_REVIEW` result when persistence remains available. Safe structured logs contain provider, configured model, prompt version, duration, success/failure category, and token counts when returned; they contain neither credentials nor raw provider responses. Evaluation persistence separately records reasoner implementation, provider, model, and prompt version alongside suite, fixture, and policy versions.

Milestone 10 adds an offline evaluation adapter around—not inside—the established triage authority path. Versioned trusted scenario data is loaded and validated separately from `ReasonerContext`; the runner invokes `TriageOrchestrator`, reads durable gateway/policy outcomes, applies transparent deterministic scoring, and persists evaluation run/case records. It cannot approve or execute actions. Scenario content cannot register tools, choose callables, replace policy, or reach the reasoner as ground truth.

Each scenario execution receives isolated alert/payload identifiers so repeated references to one fixture can produce independent immutable executions without action-ID collisions. Entity scope and evidence still derive from the referenced alert. Runs preserve suite, schema, fixture, policy, reasoner, and application versions plus linked triage execution IDs. Metrics keep disposition, escalation, tools, actions, security controls, and timing separate; no weighted quality score exists.

Milestone 8 realizes the transport boundary as a deliberately small FastAPI adapter. `bootstrap.py` is the sole trusted composition root and selects configuration, SQLAlchemy Unit of Work, fixture version, the seven-tool registry, gateway limits, policy/catalog, deterministic demo reasoner, clock/identifiers, principal provider, and routes. Request data cannot select implementations. Schema migration remains an explicit Alembic operator step; application startup never calls `create_all` or upgrades the database.

The JSON API accepts one strict provider-neutral `SecurityAlert`, durably records it with ingestion audit, and invokes triage only through `TriageOrchestrator`. Duplicate identical alerts are idempotent and conflicting reuse of an alert identifier is rejected. The empty triage command schema prevents clients from submitting tools, reasoners, result fields, policy versions, approvals, execution claims, fixture paths, or database configuration.

The current `DevelopmentPrincipalProvider` returns one fixed synthetic analyst behind a replaceable principal port. Route authorization distinguishes viewing from ingest/triage authority. It is intentionally not an identity provider: production composition fails closed, and tenant-grade object authorization remains deferred. Health is process-local; readiness performs a bounded persistence read without returning configuration.

Server-rendered Jinja pages are read-only and autoescaped. They present source and assessed severity separately, model-reported confidence as non-calibrated presentation data, escalation, policy metadata, evidence provenance, tool attempts, catalog-owned action risk/approval/execution support, and the durable audit timeline. They contain no approval or action controls. Because there is no cookie authentication and no browser mutation route, Milestone 8 has no CSRF token; all mutations are JSON API POSTs and no unsafe GET mutation exists. Any future cookie-authenticated browser mutation must add CSRF protection before it is enabled.

Milestone 9 adds a separate `ApprovalService` and `ActionExecutor` port. Policy-accepted actions persist their policy version beside immutable action material. An approval decision resolves that trusted record, verifies that the enforced result requires approval, binds the action digest and policy version, records the configured reviewer, and derives expiry exclusively from trusted configuration and clock. One unique terminal decision exists per action; an identical retry returns it, while contradictory decisions fail.

Execution reloads the action, enforced result, catalog definition, approval, and any prior execution. It independently verifies catalog membership, policy acceptance, approval requirement, digest, target/parameters through the digest, policy version, decision, expiry, historical reviewer authority, current actor authority, uniqueness, and `SIMULATED_ONLY` support. It persists `EXECUTING` plus a start audit before invoking the capability-free simulator, then atomically persists `SUCCEEDED` or `FAILED` with its audit. Durable success is never returned when the final transaction fails.

Approved decisions remain immutable historical facts. Expiry is a derived `APPROVED -> EXPIRED` lifecycle state evaluated against the trusted clock; it does not rewrite the decision. Rejected decisions remain terminal and have no expiry. Database uniqueness prevents multiple decisions or successful executions per action.

Browser approval, rejection, and simulation use POST forms with an unpredictable HttpOnly development-session cookie and an HMAC token bound to that cookie. JSON API operations do not authenticate with that cookie and remain outside this CSRF mechanism. Templates autoescape reviewer text and action material. The default local principal is the fixed synthetic reviewer; production composition continues to fail closed.

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

Milestone 7 realizes this boundary as a capability-free `AgentReasoner` port. `ReasonerContext` contains only the normalized alert, sanitized accumulated tool evidence, iteration count, and informational remaining call/iteration counts. It contains no gateway, registry, callable, repository, session, credential, policy object, approval, or executor. The offline `FakeReasoner` replays a deterministic script and records supplied contexts; it performs no prompting or network access.

`TriageOrchestrator` owns the bounded state machine: persist `RUNNING`; request one reasoner step; assign an application-controlled globally unique invocation identifier to any semantic tool proposal; route it exclusively through `ToolGateway`; transactionally persist each invocation and audit event; accumulate provenance-linked evidence; validate candidate evidence and tool-call references against the current execution; apply deterministic policy; then atomically persist actions, final result, terminal state, and policy/terminal audit events. The reasoner can propose but cannot choose canonical persistence identity, call, authorize, persist, approve, or execute.

Trusted limits independently bound reasoning iterations, overall elapsed time (including each reasoner call), gateway total/per-tool calls, evidence-item count, and serialized context size. A typed `NOT_FOUND` is useful evidence and may continue. Any denied or failed tool outcome terminates conservatively into durable review; repeated calls therefore cannot loop. Invalid output, exceptions, exhausted bounds, fabricated references, and policy-safe-review results likewise terminate with stable orchestration reason codes. The current synchronous timeout wrapper cannot forcibly terminate a non-cooperative Python thread, so future provider adapters must use cancellation-aware I/O.

Execution creation uses a unique idempotency key. A repeated request returns the already durable result without running the reasoner again. Each tool attempt commits with its audit event, while final result/state/audit share one transaction. Replay lookup, start persistence, tool-iteration persistence, and finalization failures emit only stable category, stage, root exception class, execution ID, and correlation ID. When an execution exists, a separate best-effort transaction marks it `FAILED` and appends the same sanitized diagnostic; if recovery also fails, `RECOVERY_FAILED` telemetry identifies the recovery stage and the earlier execution may remain `RUNNING` for later operational recovery. A non-durable outcome never claims a tool or result was persisted. Database uniqueness prevents two final results for one execution, but distributed worker coordination and stale-running recovery remain future hardening concerns.

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

Milestone 3 establishes the pre-gateway contract: each tool has an immutable typed request and response, static name/version/access/classification/timeout metadata, and a discriminated `FOUND | NOT_FOUND` outcome carrying tool and fixture provenance. Every initial adapter is read-only and classified `SYNTHETIC_DEMO`. Authorization, alert scope, budgets, and duplicate-call controls remain exclusively gateway responsibilities.

Fixture `v1` owns a fixed reference time and recent-sign-in window, so collection does not depend on the wall clock. The dataset is validated as one coherent snapshot before adapter construction, including identifier uniqueness and identity/device/sign-in/IP/MFA/alert relationships. Fixture versions are selected explicitly and never upgraded implicitly.

Milestone 4 makes this boundary executable. `ToolRegistry` is an immutable mapping whose allowlist contains exactly the seven approved evidence-tool identities. Trusted composition code supplies implementations; untrusted requests can only look up a name and cannot register or resolve a callable. Registration rejects unknown identities, duplicate names, state-changing capability, and invalid timeouts.

The reasoner proposes only a tool name and arguments; its strict provider-facing schema has no invocation-ID field. Before `ToolGateway` receives the resulting `ProposedToolRequest`, the orchestrator assigns the authoritative globally unique invocation ID. The trusted `ToolExecutionContext` contains alert-derived normalized entity keys, fixed execution budgets, correlation identifiers, duplicate-call state, and an in-memory invocation-record sink. Exact Pydantic request validation, including rejection of extra fields, occurs before authorization. User, device, and canonical IP arguments must match the established alert scope; fixture existence never grants access. Calls are fingerprinted from tool identity plus canonical validated JSON arguments, not from invocation identity. The first permitted call consumes total and per-tool budget; a repeated fingerprint is denied rather than cached or re-executed. Identical semantic proposals in different executions are permitted and receive distinct canonical invocation IDs.

Input and output byte limits are measured over deterministic compact JSON. Adapter execution is bounded by the lesser of immutable tool metadata and the trusted gateway timeout cap. Outcomes are validated again against the registered response contract and returned in a sanitized gateway envelope. Every attempted invocation produces a structured in-memory record for Milestone 5 persistence; internal exception details are not returned.

The current timeout wrapper is intentionally minimal for synchronous deterministic fixtures. A timed-out Python thread cannot be forcibly terminated, so future network-backed adapters must use cancellation-aware I/O and an asynchronous or process-isolated execution mechanism before registration. No network adapter is enabled in this milestone.

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

Milestone 6 implements policy version `1.0.0` as pure application logic. `CandidateAssessment` is explicitly advisory and contains no policy version, approval classification, authorization scope, or execution authority. `PolicyDecision` contains the enforced `TriageResult`, stable reason codes, accepted and rejected action identities, and the policy version for later audit persistence.

The minimum-evidence rule is deliberately conservative and simple: `BENIGN`, `SUSPICIOUS`, and `MALICIOUS` require at least one typed, traceable evidence reference. Missing evidence, invalid cross-references, malformed candidate data, unknown actions, invalid action parameters, unsupported target types, and out-of-scope targets force `NEEDS_REVIEW` and human escalation. Confidence remains an uncalibrated model report in the closed `0..1` Decimal range; it never grants action authority or bypasses approval.

### Action catalog, approval, and execution

Reasoner recommendations contain semantic action data only: catalog action type, target, allowed parameters, and rationale. They do not contain a canonical action identifier. Deterministic policy validates catalog membership, target scope, and parameter schema before creating a canonical `ActionProposal` with an application-generated globally unique identifier. Identical recommendations in separate executions therefore remain separate approval-bound records, while idempotent replay returns the already-persisted result without generating another action. A central catalog assigns each action a risk level and approval requirement. The six named high-impact actions are always approval-required.

The immutable initial catalog registers `disable_account`, `revoke_sessions`, `reset_password`, `isolate_device`, `delete_email`, and `remove_privilege`, all at risk `HIGH_IMPACT`, version `1.0.0`, approval-required, and `SIMULATED_ONLY`. Account/session/password/email/privilege actions target a scoped user; device isolation targets a scoped device. Email deletion requires a message identifier and privilege removal requires a privilege identifier; the other initial actions accept no parameters. Candidate text or extra metadata cannot register actions or alter these definitions.

The authority chain is explicit: the LLM recommends; deterministic policy decides what is permitted; a human approval will authorize high-impact actions; a separate executor will eventually perform an approved action. This milestone implements only the first two parts and does not approve or execute anything.

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

Milestone 5 implements these records with SQLAlchemy 2.x adapters behind narrow repository ports. ORM mappings remain in `adapters/persistence`; domain and application contracts contain no SQLAlchemy types. Material immutable contracts are serialized as structured JSON for exact reconstruction while query-critical values—including source and assessed severity, state, identifiers, timestamps, and confidence—also have normalized columns. Confidence uses `NUMERIC(38, 18)`. UTC timestamps use bounded ISO 8601 text so SQLite cannot discard timezone information; domain reconstruction validates and normalizes them back to aware UTC values. These portable SQL/JSON/numeric choices also work on PostgreSQL, although PostgreSQL integration testing remains release-hardening work.

`SqlAlchemyUnitOfWork` owns one session and transaction. Repositories stage records but never commit. An explicit flush can order dependent records without ending atomicity; commit failure is sanitized and rolls back. A state change and its audit event therefore share one commit or one rollback. The audit repository exposes append and query operations only—no update or delete API—and audit payloads are structured, schema-versioned, and bounded to 16 KiB.

Alembic revision `0001_initial_persistence` is the sole production schema-creation path. Local development defaults to `sqlite:///security-triage-agent.db`; operators run `python -m alembic upgrade head`, and CI verifies both a real fresh SQLite upgrade and offline migration rendering. `Base.metadata.create_all()` is not used by application startup or migration tests.

Append-only here is an application interface property, not cryptographic immutability. A database administrator or compromised process can modify SQLite directly. Hash chaining, signed export, immutable external storage, and an outbox remain compatible future hardening options and are intentionally not implemented now.

M12A adds an explicit operator recovery use case (`--recover-stale`). Using a trusted UTC clock and configured thresholds, it selects only stale `RUNNING` triage executions and stale `EXECUTING` simulated-action attempts. Each is transitioned to `FAILED` with a stable category and an audit event in one Unit of Work. It never infers success, invokes a reasoner, reruns a tool/action, or operates from a read path; repeated invocation is idempotent. Recovery is operator-invoked rather than automatic at startup so its scope and audit actor remain visible.

Production mode currently refuses startup because a production identity provider and tenant boundary do not exist. Local secrets enter only through typed configuration; a future Azure deployment should inject `OPENAI_API_KEY` from Key Vault using workload Managed Identity without coupling domain/application code to Azure SDKs. See [secret management](secret-management.md).

Provider success/failure telemetry contains provider, configured model, prompt version, duration, execution ID, correlation ID, sanitized failure category, and token counts when the SDK returns them. Missing usage remains missing rather than zero. Durable token accounting is deferred until a typed provider-observation port can preserve it without mixing infrastructure metadata into reasoner output.

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
- Action parameters are structured JSON values and are deep-frozen after validation. The action digest is SHA-256 over canonical JSON containing the catalog action identifier, normalized target, and parameters. Canonical action ID and reviewer-facing rationale are intentionally outside the digest; approvals independently bind the application-generated action ID, material digest, and policy version.
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
