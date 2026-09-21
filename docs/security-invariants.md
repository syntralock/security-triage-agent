# Security invariants

These invariants are release gates. Enforceable items have automated regression coverage; this list is the concise review index.

- A reasoner receives data only and cannot execute a tool directly.
- Every tool proposal passes through `ToolGateway`; only the seven registered read-only synthetic evidence tools are callable.
- Application code, never provider output, generates canonical tool-invocation and recommended-action identifiers.
- Alert-derived entity scope cannot be expanded by the model or fixture existence.
- Model output cannot register an action, alter deterministic policy, classify action risk, approve an action, or execute remediation.
- Every initial high-impact action requires an explicit human approval.
- Approval binds the canonical action, material digest, policy version, reviewer, decision, and—when granted—expiry. Expired or rejected approval cannot execute.
- Execution reloads and revalidates the persisted action and approval immediately before simulation.
- Evidence and tool references must belong to the current execution.
- State changes and their audit events commit atomically; failure never becomes a successful security decision.
- Stale `RUNNING` triage and stale `EXECUTING` simulation records recover only to `FAILED`; recovery never infers success or reruns work.
- Production cannot silently use the development identity. Until a production IdP exists, production startup is refused.
- Secrets, raw prompts, raw provider responses, authorization headers, evidence contents, and chain-of-thought are excluded from logs and audit metadata.
- All demonstrations and evaluations use synthetic data. Remediation remains simulated only.

