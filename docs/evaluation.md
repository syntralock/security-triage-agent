# Deterministic Evaluation Framework

Milestone 10 establishes measurement before any external-model adapter exists. Evaluation ground truth is trusted versioned data; the reasoner neither receives it nor scores itself.

## Authority and data flow

The runner loads a strict scenario suite, resolves its referenced synthetic alert, and invokes the same `TriageOrchestrator` used by the application. Tool calls still cross `ToolGateway`, candidates still cross `DeterministicPolicy`, and every triage execution remains durable and auditable. Evaluation never creates an approval or invokes an action executor.

Scenario metadata—including expected dispositions, escalation, tools, actions, scoring expectations, and maintainer rationale—stays in the evaluator. `ReasonerContext` contains only the alert, accumulated evidence, and bounded execution counters.

Evaluation JSON is data, not executable configuration. It cannot register tools, select Python callables, replace policy, expand entity scope, or grant authority.

## Scenario schema

`evaluations/v1/manifest.json` contains a suite version, schema version, fixture version, and deterministically ordered scenarios. Each scenario declares:

- Stable scenario ID/version and a referenced fixture alert
- Primary and acceptable dispositions
- Expected escalation and assessed severity
- Required, allowed, and forbidden tool identities
- Expected catalog actions and approval-required actions
- Binary label: `MALICIOUS`, `NON_MALICIOUS`, or `AMBIGUOUS`
- Tags and a maintainer-only ground-truth rationale

Loading rejects unsupported versions, duplicate IDs, malformed enums, unknown alerts/tools/actions, fixture-version mismatches, overlapping allowed/forbidden tools, and inconsistent action expectations. Nothing is silently skipped.

## Scoring semantics

Disposition is `EXACT` when it matches the first ground-truth disposition, `ACCEPTABLE` when it matches another explicitly allowed disposition, and `FAILURE` otherwise. An expected `NEEDS_REVIEW` is therefore a valid exact outcome.

Independent components record escalation and severity matches; required, unexpected, forbidden, duplicate, successful, and denied/failed tool behavior; expected and unexpected actions; approval-requirement preservation; durable completion; orchestration reason; policy-forced safe review; reference violations; orchestration bounds; and trusted elapsed milliseconds. A correct disposition never erases a tool or security-control failure.

No opaque weighted score is produced.

### False positives and false negatives

Only scenarios labeled `MALICIOUS` or `NON_MALICIOUS` participate. `MALICIOUS` is the positive class. A malicious scenario whose actual disposition is not `MALICIOUS` is a false negative. A non-malicious scenario classified `MALICIOUS` is a false positive. `SUSPICIOUS` and `NEEDS_REVIEW` scenarios labeled `AMBIGUOUS` are excluded from both denominators. Zero denominators produce `null`, not a fabricated zero rate.

The confusion matrix uses the primary expected disposition as rows and actual dispositions—including `NEEDS_REVIEW` and `NO_RESULT`—as columns.

## Persistence and reproducibility

Alembic migrations `0003_evaluation_results` and `0004_openai_evaluation_identity` add normalized run/case identities and structured score JSON. Each run preserves suite/schema/fixture versions, reasoner label, implementation, provider, configured model, prompt version, policy version, application version, timestamps, aggregate metrics, scenario versions, and linked triage execution IDs. It stores no prompt or private chain-of-thought.

Controlled clocks can make duration deterministic in tests. Real local runs measure elapsed monotonic time, but CI does not assert wall-clock thresholds. Run IDs and timestamps may differ; material scores remain repeatable.

## CLI

After applying migrations:

```bash
python -m security_triage_agent.evaluation
python -m security_triage_agent.evaluation --scenario malicious-privileged-risk
python -m security_triage_agent.evaluation --json
```

Configuration uses `STA_DATABASE_URL`, `STA_FIXTURE_PATH`, and `STA_EVALUATION_PATH`. The text report includes component counts, FP/FN denominators, confusion matrix, tool metrics, durations, and per-case reasons. JSON emits the complete typed report.

## Initial v1 baseline

The offline deterministic demo baseline contains ten scenarios over four synthetic fixture alerts:

- Clearly benign known activity
- Suspicious denied MFA
- Strong privileged malicious indicators
- Insufficient evidence and typed `NOT_FOUND`
- High-impact recommendation with preserved approval
- No-action expectation
- Required escalation
- Forbidden/unnecessary-tool measurement
- Source-versus-assessed severity distinction

Baseline result on 2026-09-18: 10 scenarios, 6 exact dispositions, 3 explicitly acceptable alternatives, 1 failure, 7 escalation matches, 0 false positives, 0 false negatives, 10 successful tool calls, 0 required-tool omissions, and 0 forbidden calls. The failed disposition is the clearly benign scenario: the intentionally conservative demo reasoner returns `NEEDS_REVIEW` instead of `BENIGN`. This limitation is retained rather than changing ground truth to improve the score.

The small, overlapping synthetic suite is a harness baseline, not evidence of general SOC accuracy. The OpenAI adapter implements the existing `AgentReasoner` port and runs through this same harness without gaining access to ground truth or security authority.

The optional OpenAI run uses the same command after trusted environment configuration selects `openai`. It never runs automatically, never receives scenario ground truth, never creates approvals, and never executes actions. Provider failures remain visible as safe review outcomes rather than triggering a hidden demo-reasoner fallback.

**Model-reported confidence is not a calibrated probability.** It is not rewarded by scoring and cannot authorize an action.
