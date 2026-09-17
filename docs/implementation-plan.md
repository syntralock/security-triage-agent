# Implementation Plan

Status: architecture approved on 2026-09-17. Milestones 0–2 are complete; later milestones still require explicit approval. Each milestone is intentionally small, reviewable, and independently testable.

## Milestone 0 — Architecture approval

**Status:** complete.

**Deliverables:** reviewed architecture, repository structure, security decisions, open-decision resolutions, `AGENTS.md`, and this plan.

**Acceptance:** stakeholders explicitly approve or amend the proposed boundaries; severity/confidence semantics and initial authentication posture are resolved. No application code is required.

## Milestone 1 — Project foundation

**Status:** complete on 2026-09-17. Milestone 2 has not started and requires explicit approval.

Create the Python 3.12 package, dependency/tool configuration, environment settings, structured logging, test runner, Docker baseline, `.env.example`, README contribution workflow, `SECURITY.md`, and CI checks.

**Tests:** settings validation, logging redaction, import smoke test, container health/start smoke test, secret-scanning/lint/type/test commands.

**Acceptance:** a fresh checkout can run formatting, linting, type checking, and tests without network credentials; no triage behavior yet.

## Milestone 2 — Domain contracts

**Status:** complete on 2026-09-17. Milestone 3 has not started and requires explicit approval.

Implement provider-neutral alert, entity, evidence, disposition, severity, triage-result, action, approval, and execution-state models. Specify invariants and serialization contracts.

**Tests:** enum rejection, confidence bounds, UTC timestamps, escalation-reason invariant, evidence provenance, action identity/digest, execution and approval transition tables.

**Acceptance:** all required triage output fields are represented and invalid domain states cannot be constructed through public interfaces.

## Milestone 3 — Synthetic data and evidence tool contracts

Create versioned synthetic fixtures, seven typed tool interfaces/adapters, registry metadata, and fixture validation. Document how data was synthesized.

**Tests:** deterministic lookup success/not-found cases, schema validation, IPv4/IPv6 handling, fixture referential integrity, contract tests shared by every tool.

**Acceptance:** identical input plus fixture version gives identical typed output; fixtures contain no real data.

## Milestone 4 — Tool gateway security boundary

Implement allowlisting, strict argument parsing, alert-entity scoping, read-only enforcement, budgets, duplicate-call handling, timeouts, sanitized result envelopes, and audit hooks using in-memory fakes.

**Tests:** unknown tool, extra/malformed arguments, out-of-scope entity, excessive calls, duplicate calls, timeout, oversized result, prompt-injection strings treated as data.

**Acceptance:** no tool adapter can be invoked except through validated gateway rules, and every attempt has a structured outcome.

## Milestone 5 — Persistence and durable audit

Add SQLAlchemy models, repositories, unit of work, initial Alembic migration, SQLite configuration, and append-only audit records for alerts, executions, and tool calls.

**Tests:** migration upgrade on empty database, transactional state-plus-audit writes, rollback behavior, unique/idempotency constraints, immutable terminal records, repository round trips.

**Acceptance:** an execution and its tool history can be reconstructed after process restart; failed transactions do not leave misleading audit/state pairs.

## Milestone 6 — Deterministic policy and action catalog

Implement post-reasoning validation, escalation rules, evidence minimums, action catalog/risk levels, approval classification, and safe failure behavior. Register the six prohibited-without-approval actions.

**Tests:** exhaustive action catalog table, unknown action denial, high-impact approval enforcement, malformed/insufficient candidate results, confidence and escalation edge cases.

**Acceptance:** no candidate model output can remove an approval requirement or introduce an unregistered action.

## Milestone 7 — Bounded orchestration with a fake reasoner

Implement the `AgentReasoner` port, deterministic fake, bounded state machine, candidate-result validation, and triage application service. Persist all transitions and results.

**Tests:** zero/multiple tool calls, iteration and deadline exhaustion, malformed reasoner output, repeated calls, tool failure, idempotent retry, successful end-to-end triage using only fakes.

**Acceptance:** deterministic scenarios produce complete typed results and audit histories without any model or external service.

## Milestone 8 — Ingestion API and minimal review UI

Add FastAPI routes for provider-specific ingestion, execution status/result/audit views, and thin server-rendered pages. Use an explicit synthetic development principal through an authorization interface.

**Tests:** provider mapping, request size/schema rejection, idempotency, route authorization, safe error responses, HTML smoke/accessibility checks, API-to-database audit completeness.

**Acceptance:** a synthetic alert can be submitted and its completed fake-reasoner triage inspected; routes cannot bypass application services.

## Milestone 9 — Approval workflow and simulated actions

Implement proposed-action persistence, reviewer approve/reject flow, expiry/digest binding, deterministic transition enforcement, and a no-op/synthetic executor with pre-execution revalidation.

**Tests:** role separation, altered target/parameter digest, expired/replayed approval, duplicate execution, rejection, policy version mismatch, executor failure, complete audit chronology.

**Acceptance:** high-impact actions never execute without a current matching approval; the UI/API clearly distinguishes recommendation, approval, and execution.

## Milestone 10 — Evaluation framework

Implement versioned scenario schema, runner, deterministic scorer, reports, baseline scenario suite, and metrics for disposition, false positives/negatives, escalation, tool selection, and latency.

**Tests:** hand-calculated metric fixtures, denominator-zero behavior, required/allowed/forbidden tool scoring, reproducibility metadata, deterministic repeated runs.

**Acceptance:** one command produces a machine-readable and human-readable report from offline scenarios, with defined positive classes and thresholds.

## Milestone 11 — OpenAI adapter

Add the OpenAI SDK adapter behind `AgentReasoner`, strict structured output/tool calling, minimal prompt construction, provider timeouts/retries, token/latency capture, and safe provider-error mapping. Keep it optional and credential-gated.

**Tests:** mocked SDK contract cases only in normal CI: tool request, final result, invalid structure, refusal, timeout, rate limit, and unavailable provider. Run live evaluations only through an explicit opt-in command.

**Acceptance:** removing or disabling the adapter leaves all offline functionality/tests intact; provider failure leads to the documented safe state; SDK types do not leak into domain/application code.

## Milestone 12 — Hardening and portfolio release

Complete threat model, abuse cases, dependency/container hardening, rate/input limits, audit-integrity decision, observability, retention/redaction documentation, PostgreSQL compatibility test, accessibility pass, and demonstration walkthrough.

**Tests:** adversarial scenario suite, authorization matrix, migration test on PostgreSQL, concurrency/idempotency tests, container runs unprivileged, dependency and secret scans.

**Acceptance:** documented release checklist passes; known limitations are explicit; demo uses only synthetic data and simulated response actions.

## Milestone discipline

For every milestone:

1. Confirm prerequisites and acceptance criteria.
2. Add tests with the behavior, including at least one negative/security case.
3. Keep schema/API changes documented and migration-backed.
4. Record design changes in an ADR when they alter a trust boundary or public contract.
5. Report commands run, results, and remaining risks before moving on.

Milestones may be split further, but should not be combined in ways that obscure a security boundary or make review impractical.
