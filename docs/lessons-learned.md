# Lessons learned building Security Triage Agent

Security Triage Agent is an engineering case study in containing probabilistic reasoning inside deterministic
security controls. These lessons come from implementation, adversarial tests, and controlled live
experiments over synthetic scenarios. They are not claims of general SOC accuracy.

## 1. AI should reason, not hold security authority

Models are useful for correlating facts, identifying uncertainty, and explaining recommendations.
They are poor owners of authentication, authorization, policy, approval, and execution. The project
therefore treats every model response as untrusted input and keeps final authority in code and
human review.

## 2. Models should describe intent, not mint application identity

Early contracts let reasoner-provided invocation identifiers collide or become ambiguous across
executions. Canonical tool invocation IDs and action IDs now come from application code. Models
propose a tool, arguments, or action intent; trusted orchestration assigns identity and binds it to
the current transaction.

## 3. Structured output is not automatically a safe contract

A typed response does not make every provider schema portable or every value trustworthy.
Provider restrictions around open objects and union shapes required a narrow provider-facing
schema, followed by parsing into strict internal models. Validation is a trust boundary, not a
formatting convenience.

## 4. Fail closed before trying to be smarter

Timeouts, refusals, malformed output, and provider failures must not become fabricated success or
a hidden fallback that changes evaluation identity. When a valid reviewable record can be saved,
the safe outcome is `NEEDS_REVIEW`; policy, validation, and audit failures otherwise stop the flow.

## 5. Evaluation ground truth is also a hypothesis

Repeated `MALICIOUS`, `CRITICAL`, and `disable_account` expectations looked definitive in a test
manifest but were not uniquely compelled by the observable evidence. Multi-model disagreement
forced a review of the answer key. Evaluation data needs the same skepticism as model output.

## 6. Bigger models do not repair an ambiguous contract

Luna, Terra, Sol, and Astra all found risk and generally escalated, yet shared failures at undefined
disposition boundaries. Larger models spent more time or gathered more evidence without resolving
missing operational definitions. Contract quality mattered more than model size.

## 7. Better instructions can make behavior worse

An early v2 contract improved scope communication and removed artificial-environment leakage, but
also encouraged broader investigation. Tool use and deadline outcomes increased. Improving one
quality dimension can regress another, so prompt changes need bounded comparative evaluation.

## 8. Stopping rules are part of the safety contract

“Gather useful evidence” is not enough. A reasoner needs to identify the decision-relevant
uncertainty, how a proposed result could change the assessment, and why a source can resolve it.
`NEEDS_REVIEW` must count as successful completion; otherwise a model may pursue certainty until a
deadline or stop too early on shallow evidence.

## 9. Synthetic data can leak the expected answer

Words such as “synthetic,” documentation-only addresses, expected-baseline prose, and fixture
identifiers influenced reasoning even though formal ground truth was withheld. A narrow
provider-facing projection now removes artificial cues while preserving security facts and the
original normalized/audited record.

## 10. `NOT_FOUND` is not `BENIGN`

Missing evidence, empty related sources, or ordinary identity context do not affirmatively explain
a material security concern. A benign conclusion needs credible explanatory evidence and no
unresolved material indicator. When the needed fact remains unavailable, review is the bounded
outcome.

## 11. Human approval must bind exact action material

Approval of “disable this account” is too vague. The project binds the action ID and digest, type,
target, parameters, policy version, reviewer, decision time, and expiry. Any material change
invalidates approval, and the executor rechecks the authoritative state immediately before a
simulation.

## 12. Design for model failure

The goal is not an AI that never makes mistakes. The goal is a system where AI mistakes have
bounded consequences: denied tool calls, deterministic policy, explicit human decisions,
simulation-only execution, and reconstructable audit evidence.

See the [evaluation framework](evaluation.md), [v1 contract review](m12b-reasoning-evaluation-review.md),
and [controlled v1/v2 experiment](evaluations/m12b-terra-v1-v2-experiment.md) for supporting detail.
