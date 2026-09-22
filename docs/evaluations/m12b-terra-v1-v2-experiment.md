# M12B Terra v1-v2 controlled experiment

Status: completed diagnostic experiment. The current `openai-l1-v2` boundary is not frozen.

## Configuration and protocol

The experiment compared the complete versioned reasoning boundaries `openai-l1-v1` and
`openai-l1-v2`, not prompt text alone. V2 additionally included explicit authorized targets,
catalog-derived action semantics, and a neutralized provider-facing presentation. Everything
outside that boundary remained fixed: OpenAI provider, `gpt-5.6-terra`, `evaluations/v1`, fixture
`v1`, policy `1.0.0`, application commit, ToolGateway, action and approval controls, scoring,
25-second provider timeout, 30-second orchestration deadline, disabled SDK retries, and
synthetic-only data.

Three complete runs per boundary were executed in this exact interleaved order:

1. v1
2. v2
3. v2
4. v1
5. v1
6. v2

Each run used a fresh migrated SQLite database. No scenario was retried.

## Aggregate observations

| Metric | v1 (30 cases) | v2 (30 cases) |
|---|---:|---:|
| EXACT | 10 | 12 |
| ACCEPTABLE | 4 | 4 |
| FAILURE | 16 | 14 |
| Escalation matches | 25 | 24 |
| Historical malicious false negatives | 12 | 12 |
| False positives | 0 | 0 |
| Severity matches | 10 | 6 |
| Tool proposals | 118 | 142 |
| Required-tool omissions | 13 | 11 |
| Unexpected tool selections | 83 | 101 |
| Out-of-scope proposals | 3 | 0 |
| Orchestration-bound outcomes | 3 | 14 |
| Artificial-environment leakage summaries | 8 | 0 |
| Mean scenario duration | 16.38 seconds | 21.86 seconds |

V2 eliminated observed scope errors and substantive evaluation/artificial-environment leakage.
It nevertheless requested substantially more evidence, selected more historically unexpected
tools, reached orchestration bounds much more often, and increased mean latency by about 33.5%.
Its modest historical EXACT improvement did not extend to the four historical malicious cases.

## Interpretation limits

The historical `evaluations/v1` MALICIOUS/CRITICAL labels and expected `disable_account` action
are not uniquely justified under the subsequently approved reasoning definitions. A
`SUSPICIOUS/HIGH` result with escalation and proportionate containment can therefore be
semantically defensible while still scoring as a historical failure. In the experiment, v1
returned several such candidates. V2 returned one, but most v2 historical-malicious cases ended
in deterministic safe review after a deadline rather than in a completed model assessment.

The directional conclusion is that current v2 improves scope communication and leakage control
but regresses investigation stopping and completion reliability. The next diagnostic question
is why it continues requesting evidence after a defensible assessment may already be available.
This experiment contains only three stochastic runs per boundary over ten overlapping synthetic
scenarios and makes no claim of statistical significance, general SOC accuracy, or production
fitness.

No secret, raw prompt, raw provider response, or private chain-of-thought is recorded here.

## M12B.4 stopping-behavior study

A preregistered four-scenario v2 study added bounded reviewer-facing `evidence_goal` metadata and
ran `benign-known-signin`, `malicious-privileged-risk`, `insufficient-evidence-review`, and
`typed-not-found-evidence` once each on Terra. Eighteen allowlisted, in-scope requests were made;
each goal was durably audited without becoming evidence or affecting gateway authority.

The benign case completed defensibly after three useful calls. The Riley case made five calls,
including derivative related-alert correlation, then hit the orchestration deadline before
returning a candidate. Each missing-evidence case made five calls and converted a material
NOT_FOUND gap plus several empty sources into high-confidence BENIGN. Post-hoc review found five
completed calls after the earliest defensible stopping points. The recurring pattern was coherent
but certainty-seeking investigation: the reasoner treated any potentially informative source as
justification for another request, did not treat NEEDS_REVIEW as successful completion, and used
broad negative evidence as a substitute for a missing material fact.

## Approved M12B.5 stopping correction

The reviewed correction reframes investigation around the **minimum defensible assessment**, not
maximum available certainty. Before requesting evidence, v2 must identify a decision-relevant
uncertainty, a plausible result that would materially change disposition, severity, escalation,
or minimum necessary response, and a source reasonably capable of resolving it. Mere possible
context is insufficient. NEEDS_REVIEW is explicitly a successful bounded conclusion; material
NOT_FOUND permits at most one targeted alternative source when it can establish the missing fact;
empty unrelated sources cannot replace that fact. Corroboration must be decision-relevant, while
residual severity and action uncertainty should be stated or handled with narrower proportionate
recommendations rather than exhaustive investigation.

This is a general reasoning-contract correction derived from observed stopping behavior, not a
scenario rule or attempt to match historical labels. It names no scenario, tool, expected answer,
or benchmark-specific evidence. Scope communication, anti-leakage presentation, ToolGateway,
policy, approval, and execution controls remain unchanged. The correction is experimental and no
improvement is claimed until separately tested.
