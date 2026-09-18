# Threat Model

Status: approved baseline. Revisit this document whenever a trust boundary, external integration, action type, or deployment model changes.

Milestone 4 implements trust boundaries 4 and 5 for the initial synthetic evidence tools: a closed read-only registry, exact request/output validation, alert-derived entity scope, deterministic call budgets and duplicate denial, bounded input/output, timeouts, sanitized failures, and one in-memory invocation record per attempt. Durable storage of those records remains Milestone 5 work.

Milestone 5 implements trust boundary 6 with parameterized SQLAlchemy repositories, database constraints, explicit Unit of Work transactions, sanitized persistence failures, versioned migrations, bounded structured audit payloads, and append-only repository semantics. SQLite audit data is not tamper-proof against an administrator or compromised process.

Milestone 6 makes action and post-reasoning policy metadata code-owned and immutable. All initial actions are high-impact and approval-required. Candidate content cannot register actions, change risk or approval requirements, supply policy identity, expand target scope, claim approval, or use confidence/severity/disposition to gain authority. Unknown and invalid conditions fail to an auditable escalated review result.

Milestone 7 confines reasoner authority to typed proposals over a data-only context. The orchestrator owns iteration/deadline/context bounds, gateway routing, current-execution evidence references, policy invocation, lifecycle, idempotency, and transactional audit. Fabricated or cross-execution references and candidate claims of approval/execution fail safely. The deterministic fake has no network or provider dependency.

Milestone 8 exposes those services through FastAPI without moving authority into routes or templates. A trusted composition root selects the database, fixture set, tool registry, policy, gateway, and deterministic demo reasoner. HTTP bodies cannot select these dependencies or claim a principal, policy result, approval, or execution. A fixed development-only principal crosses an explicit authorization interface, and production configuration refuses to use it. JSON inputs are strict and size-limited, errors are sanitized, templates autoescape untrusted content, and the browser UI is read-only. There are no cookies or browser state-changing operations in this milestone; API mutations are POST-only and CORS is not enabled. Production identity, tenant isolation, rate limiting, and CSRF protection for any future cookie-authenticated mutation remain deferred controls.

## Scope and assumptions

This model covers synthetic alert ingestion, triage orchestration, model reasoning, evidence tools, persistence, human approval, simulated action execution, evaluation, API, and minimal UI.

Initial assumptions:

- The application runs as a modular monolith with SQLite locally and a future PostgreSQL option.
- Evidence comes only from deterministic synthetic fixtures in the initial release.
- Response actions are simulated; no production identity, endpoint, email, or security platform is connected.
- A model provider is optional. Offline operation uses a deterministic fake reasoner.
- Transport security, host hardening, and identity-provider integration are deployment responsibilities, but application authorization hooks and safe defaults remain in scope.

## Assets

- Integrity of alert, evidence, triage, approval, and action records.
- Integrity and availability of deterministic policy and the action catalog.
- Accuracy and provenance of evidence used for decisions.
- Reviewer identity and authorization context.
- Model/API credentials and application configuration.
- Audit history and evaluation results.
- Availability and cost limits for the triage service and model provider.
- The project's claim that all demonstration data is synthetic.

## Actors

- Alert submitter: submits synthetic provider-shaped alerts.
- Analyst/reviewer: inspects triage and may approve or reject actions.
- Administrator: configures deployment and policy.
- Agent reasoner: untrusted advisory component that requests tools and proposes assessments.
- Evidence adapter: returns typed synthetic evidence.
- Action executor: performs only authorized, approved catalog actions; simulated initially.
- Attacker: may submit malicious alerts, manipulate evidence/integration responses, steal a low-privilege session, replay requests, or attempt resource exhaustion.

## Trust boundaries

1. Client/UI to FastAPI: all input and identity claims require validation.
2. Provider payload to normalized domain alert: descriptive content is untrusted data.
3. Application to model provider: minimize outbound context and distrust every returned field.
4. Orchestrator to tool gateway: model-selected calls cross a deterministic authorization boundary.
5. Tool gateway to evidence adapter: adapter results are untrusted until schema-validated.
6. Application to database: transactions and constraints preserve state/audit integrity.
7. Reviewer to approval service: authenticated identity and role are required.
8. Approval service to action executor: exact action binding and fresh authorization are required.
9. Configuration/secrets to process: secrets must not enter repository, model context, logs, or responses.

## Primary threats and controls

| Threat | Example impact | Required controls | Verification |
|---|---|---|---|
| Prompt injection in alert/evidence | Model ignores policy or requests unsafe capability | Label content as data; fixed higher-priority instructions; allowlisted typed tools; post-model policy; no direct executors | Adversarial fixtures and forbidden-tool tests |
| Hallucinated tool/evidence/action | Unsupported decision or remediation | Closed registries/enums; evidence IDs must resolve; reject unknown values; default to review | Contract and negative orchestration tests |
| Broken object-level authorization | User reads another case or queries unrelated identity | Application authorization service; alert-bound entity scope; opaque IDs; deny by default | Authorization matrix and cross-entity tests |
| Approval bypass | High-impact action runs without review | Separate approval service; catalog risk; exact action digest; actor separation; executor recheck | Transition-table and no-approval tests |
| Approval replay or stale approval | Changed/expired action executes | Nonce/unique action ID; expiry; one-time state transition; policy/target/parameter digest | Replay, expiry, and mutation tests |
| TOCTOU between approval and action | Current state no longer matches reviewed state | Revalidate approval, authorization, policy version, target, and parameters immediately before execution | Concurrency and stale-policy tests |
| Audit loss or tampering | Decisions cannot be reconstructed | Same-transaction state/audit writes; append-only application API; restricted DB role; backups; preserve an upgrade path for hash chaining, signed export, or immutable storage | Rollback, mutation-denial, restore tests |
| Partial or duplicate processing | Conflicting results/actions | Idempotency keys; unique constraints; explicit lifecycle; immutable terminal results | Retry and concurrency tests |
| Resource/cost exhaustion | Service outage or uncontrolled model spend | Input limits; rate limits; call/iteration/token budgets; deadlines; bounded results; circuit breaking | Limit and timeout tests |
| Sensitive-data leakage | Secrets or identifiers leak to provider/logs | Synthetic-only data; context minimization; structured redaction; no prompt/log secrets; retention policy | Secret scanning and redaction tests |
| Malformed/oversized model output | Parser failure or resource use | Structured outputs; strict size/schema validation; safe failure to review | Fuzz/property and oversized-output tests |
| Tool/integration compromise | Fabricated or malicious evidence | Output schemas; provenance/version; content treated as data; timeouts; adapter isolation | Adapter contract and injection tests |
| SQL/template/log injection | Data corruption or analyst compromise | ORM parameterization; auto-escaped templates; structured logging; safe error mapping | Injection payload tests and static analysis |
| CSRF/session abuse in approval UI | Unauthorized approval/rejection | Same-site secure cookies, CSRF protection, reauthentication as appropriate, server-side authorization | Route security tests |
| Supply-chain compromise | Malicious code or image | Constrained dependencies; lockfile; provenance/scanning; minimal unprivileged image | Dependency and container scans |
| Metric manipulation or benchmark leakage | Misleading portfolio claims | Immutable scenario versions; held-out cases; deterministic scorer; report configuration and exclusions | Scorer unit tests and review process |

## Abuse cases that must fail safely

- An alert description says to call an unregistered tool or disable an account.
- A model invents a user ID not present in the alert's authorized entity set.
- A tool result contains text formatted like model/system instructions.
- A candidate result omits evidence, uses confidence above one, or proposes an unknown action.
- An analyst approves device isolation and the target or parameters change afterward.
- Two workers process the same idempotency key or attempt the same approved action.
- The model provider is unavailable after some evidence calls have completed.
- The audit write fails while a state transition is being committed.

Expected behavior is rejection, rollback where applicable, and a durable safe terminal/reviewable state. No prohibited action may occur.

## Residual risk and deferred controls

- Model assessments can still be wrong despite bounded capabilities; human escalation and evaluation measure but do not eliminate this risk.
- A database administrator can alter local SQLite data. Hash chaining is explicitly deferred; signed export, hash chaining, or immutable external storage may be added later without replacing the core audit event model.
- Development principals do not provide production-grade authentication. The UI must label this limitation until a real identity provider is integrated.
- Synthetic fixtures may accidentally resemble real entities. Fixture-generation guidance and review are required, and reserved example domains/IP ranges should be used.
- A compromised application process can access its runtime credentials. Secret managers, workload identity, process isolation, and egress policy belong to a later deployment-hardening design.

## Security review checklist for new tools or actions

Before registering a new tool or action, document and test:

1. Input/output schema and maximum sizes.
2. Read/write capability and action risk classification.
3. Required role, entity scope, and target constraints.
4. Timeout, retry, idempotency, and failure semantics.
5. Data classification, provider exposure, logging, redaction, and retention.
6. Prompt-injection and malicious-result handling.
7. Audit events and evidence provenance.
8. Approval, expiry, revalidation, and rollback/compensation behavior.
9. Synthetic test fixtures and negative/abuse cases.

No new state-changing adapter is enabled merely by exposing it to the model.
