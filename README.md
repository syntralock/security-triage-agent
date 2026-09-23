# Security Triage Agent

Security Triage Agent is an open-source, self-hosted demonstration of a bounded Level 1 security triage
agent. It investigates synthetic alerts, records evidence, proposes an assessment, and recommends
cataloged actions without giving an AI model authority over security controls.

> **AI reasons. Deterministic controls authorize. Humans decide.**

## Why Security Triage Agent Exists

LLMs can help correlate evidence and explain security events, but their output is probabilistic.
The project explores a safer architecture: model output is untrusted advisory input surrounded by
typed schemas, an authorization gateway, deterministic policy, exact approval binding, simulated
execution, and durable audit history.

## How It Works

```text
Alert
  ↓
AI or deterministic reasoner
  ↓ proposes
ToolGateway
  ↓ authorizes
Read-only synthetic evidence
  ↓
Advisory assessment
  ↓
Deterministic policy
  ↓
Human review
  ↓
Approval-bound action
  ↓
Simulation only + durable audit
```

This is the current demo architecture. Provider telemetry and remediation are not connected.

## What Works Today

- Provider-neutral alert ingestion and normalized persistence
- Bounded evidence collection through a typed, allowlisted `ToolGateway`
- Evidence provenance, entity scoping, budgets, and deterministic policy
- Deterministic offline reasoner and optional experimental OpenAI reasoner
- Human approval or rejection bound to the exact action, target, parameters, digest, and expiry
- Simulation-only action execution with executor revalidation
- Append-only application audit events and a local analyst web interface
- Versioned synthetic fixtures and deterministic evaluation scenarios

## What It Does Not Do

- No autonomous alert closure, approval, or real remediation
- No real provider telemetry or provider credentials exposed to a model
- No production identity provider, tenant isolation, or production deployment architecture
- No claim of calibrated AI confidence, general SOC accuracy, or production readiness
- No claim that local audit storage is externally tamper-evident

## Quick Start

Requirements: Docker with Compose and Git.

```bash
git clone https://github.com/syntralock/security-triage-agent.git
cd security-triage-agent
cp .env.example .env
docker compose up --build
```

Open <http://127.0.0.1:8000>. Compose applies migrations, starts the unprivileged local service,
and persists demo data in a named volume. The default deterministic reasoner requires no API key
and makes no network model request.

To reset local demo data:

```bash
docker compose down --volumes
```

This deletes the local Compose database volume. See [self-hosting](docs/deployment.md) for
configuration, OpenAI opt-in, backup, and security limitations. Python contributors should use
the [development guide](docs/development.md).

## Security Model

The model cannot choose arbitrary functions, URLs, SQL, paths, or network destinations. It can
request only registered read-only evidence tools. Application code validates and authorizes every
request, applies policy after parsing model output, creates canonical identifiers, and owns all
approval and execution state.

Read the [architecture](docs/architecture.md), [security invariants](docs/security-invariants.md),
[threat model](docs/threat-model.md), and [security policy](SECURITY.md).

## AI Reasoning

AI reasoning is advisory. `openai-l1-v1` is a frozen historical baseline. `openai-l1-v2` is an
experimental contract with better scope communication and stopping behavior, but it is not the
default and is not a production-quality claim. Provider failures fail closed to a reviewable safe
state when persistence remains available.

See the [evaluation framework](docs/evaluation.md), [recorded evaluations](docs/evaluations/), and
[lessons learned](docs/lessons-learned.md). No raw prompts, provider responses, secrets, or private
chain-of-thought are retained in reports.

## Project Status

`v1.0.0-demo` is a local/self-hosted portfolio release using synthetic evidence and
simulation-only actions. The fixed development identity is not production authentication.
Read-only provider integration is future work; production identity and any write capability need
separate security design and review.

## Documentation

- [Architecture](docs/architecture.md)
- [Security invariants](docs/security-invariants.md) and [threat model](docs/threat-model.md)
- [Self-hosting](docs/deployment.md) and [development](docs/development.md)
- [Evaluation](docs/evaluation.md) and [lessons learned](docs/lessons-learned.md)
- [Roadmap](docs/roadmap.md) and [release readiness](docs/release-readiness.md)
- [Dependency locking](docs/dependency-locking.md) and [third-party licenses](docs/third-party-licenses.md)

## Contributing

Contributions are welcome when they preserve the project’s authority boundaries. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) and the security invariants. Never submit real alert data,
credentials, customer information, or provider identifiers.

## License

Security Triage Agent project source is licensed under the [Apache License 2.0](LICENSE). Third-party
dependencies retain their own licenses; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
