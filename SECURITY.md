# Security Policy

## Supported versions

The project is pre-release. Security fixes are applied to the current `main` branch only.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting feature for this repository when available. If private reporting is unavailable, contact the repository owner privately and include:

- a concise description and potential impact;
- affected revision or version;
- reproducible steps using synthetic data only;
- any suggested mitigation.

Do not include real credentials, corporate data, production identifiers, or other sensitive material. Allow maintainers reasonable time to investigate before public disclosure.

## Security boundaries

This project is a demonstration system and is not approved for production SOC data or production remediation. All examples and reports must use synthetic data. The initial implementation simulates remediation and must not be connected to real identity, endpoint, email, or security-provider systems.

The optional AI component has reasoning and recommendation authority only. Deterministic application code owns authorization, policy, approvals, execution, state transitions, and audit recording. See [the architecture](docs/architecture.md), [threat model](docs/threat-model.md), and [security invariants](docs/security-invariants.md).

## Secrets

No secret is required for the offline development and test workflow. Local API use may store `OPENAI_API_KEY` in the explicitly ignored `.env.local`, restricted to the local user; never print it or pass it on a command line. Never commit API keys, tokens, passwords, cookies, private certificates, real alert payloads, or production connection strings. If a secret is exposed, revoke it immediately and report the exposure privately. The intended Azure flow is Managed Identity to Key Vault to the application's `OPENAI_API_KEY` configuration boundary; see [secret management](docs/secret-management.md).

Production mode currently refuses to start because a production identity provider is not implemented. This repository demonstrates bounded controls with synthetic data; it is not approved for production SOC data or real remediation.

## Dependency and code checks

The supported verification command is `make check`. It performs formatting verification, linting, strict type checking, tests with coverage enforcement, static security analysis, and repository secret detection. CI runs the same categories of checks without external service credentials.
