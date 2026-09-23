# Security policy

## Supported versions and response expectations

The current supported line is `v1.0.0-demo` and the latest `main` branch. This is a local/demo
release, not a production service. No response or remediation SLA is offered.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private vulnerability
reporting when it is available for this repository. Include:

- a concise description and potential impact;
- the affected revision or version;
- reproducible steps using synthetic data only;
- any suggested mitigation.

Do not include real credentials, corporate data, production identifiers, or other sensitive
material. Allow maintainers reasonable time to investigate before coordinated public disclosure.

**HUMAN DECISION REQUIRED:** before making the repository public, enable and test GitHub private
vulnerability reporting. No separate public security email has been authorized. If the private
channel is unavailable, do not publish vulnerability details in an issue.

## Security boundaries

Security Triage Agent is not approved for production SOC data or production remediation. All examples and
reports must use synthetic data. Evidence adapters are fixtures and action execution is simulated.

The optional AI component has reasoning and recommendation authority only. Deterministic code owns
authorization, policy, approvals, execution, state transitions, and audit recording. See the
[architecture](docs/architecture.md), [threat model](docs/threat-model.md), and
[security invariants](docs/security-invariants.md).

## Secrets

No secret is required for the offline demo or test workflow. OpenAI opt-in may read
`OPENAI_API_KEY` from the explicitly ignored `.env` or `.env.local`; restrict the file to the local
user and never print the value or pass it on a command line. Never commit API keys, tokens,
passwords, cookies, private certificates, real alert payloads, or production connection strings.
If a secret is exposed, revoke it immediately and report the exposure privately.

Production mode refuses startup because a production identity provider is not implemented.

## Dependency and code checks

Run `make check`. It performs formatting verification, linting, strict type checking, tests with
coverage enforcement, migration and fixture/evaluation validation, dependency checks, Bandit, and
secret detection. CI runs these checks without external service credentials.
